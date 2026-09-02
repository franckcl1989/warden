import { createPinia, setActivePinia } from 'pinia';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { setSessionExpiredHandler } from '@/api/client';
import { useAuthStore } from '@/stores/auth';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

const USER = {
  id: 'u-1',
  username: 'admin',
  display_name: '管理员',
  role: 'admin',
  status: 'active',
  must_change_password: false,
  last_login_at: null,
  created_at: '2026-09-01T00:00:00Z',
  updated_at: '2026-09-01T00:00:00Z',
  version: 1,
};

describe('auth store（PLT-01）', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    setSessionExpiredHandler(null);
  });

  it('login 成功保存用户、CSRF 票据与会话到期时间', async () => {
    setActivePinia(createPinia());
    const fetchMock = vi.fn(async () =>
      jsonResponse({
        user: USER,
        csrf_token: 'csrf-abc',
        session_expires_at: '2026-09-03T00:00:00Z',
      }),
    );
    vi.stubGlobal('fetch', fetchMock);
    const auth = useAuthStore();
    await auth.login('admin', 'password');
    expect(auth.user?.username).toBe('admin');
    expect(auth.isAuthenticated).toBe(true);
    expect(auth.isAdmin).toBe(true);
    expect(auth.csrfToken).toBe('csrf-abc');
    expect(auth.sessionExpiresAt).toBe('2026-09-03T00:00:00Z');
    expect(auth.mustChangePassword).toBe(false);
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(init.method).toBe('POST');
    // 登录请求发生在取得票据之前，不携带 CSRF 头
    expect(init.headers).not.toHaveProperty('X-CSRF-Token');
    // 登录后变更请求自动携带内存中的 CSRF 票据
    await auth.logout();
    const [, logoutInit] = fetchMock.mock.calls[1] as unknown as [string, RequestInit];
    expect(logoutInit.method).toBe('POST');
    expect(logoutInit.headers).toMatchObject({ 'X-CSRF-Token': 'csrf-abc' });
  });

  it('login 失败抛出 ApiError 并保留 code，不进入登录态', async () => {
    setActivePinia(createPinia());
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse(
          {
            error: {
              code: 'validation_failed',
              message: '用户名或密码错误',
              details: { field: 'password', reason: 'invalid_credentials' },
              request_id: 'req-01',
            },
          },
          422,
        ),
      ),
    );
    const auth = useAuthStore();
    await expect(auth.login('admin', 'wrong')).rejects.toMatchObject({
      code: 'validation_failed',
      request_id: 'req-01',
    });
    expect(auth.isAuthenticated).toBe(false);
  });

  it('logout 调用撤销接口并清空本地状态', async () => {
    setActivePinia(createPinia());
    const fetchMock = vi.fn(async () => jsonResponse({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);
    const auth = useAuthStore();
    auth.user = USER;
    auth.csrfToken = 'csrf-abc';
    await auth.logout();
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/auth/logout',
      expect.objectContaining({ method: 'POST' }),
    );
    expect(auth.user).toBeNull();
    expect(auth.csrfToken).toBeNull();
    expect(auth.isAuthenticated).toBe(false);
  });

  it('refreshMe 恢复会话与权限', async () => {
    setActivePinia(createPinia());
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse({
          user: USER,
          permissions: ['device.read', 'user.manage'],
          session_expires_at: '2026-09-03T00:00:00Z',
        }),
      ),
    );
    const auth = useAuthStore();
    await auth.refreshMe();
    expect(auth.user?.role).toBe('admin');
    expect(auth.permissions).toEqual(['device.read', 'user.manage']);
  });

  it('refreshMe 401 触发会话失效处理器', async () => {
    setActivePinia(createPinia());
    const handler = vi.fn();
    setSessionExpiredHandler(handler);
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse(
          {
            error: { code: 'session_expired', message: '会话已过期', details: {}, request_id: 'r' },
          },
          401,
        ),
      ),
    );
    const auth = useAuthStore();
    await expect(auth.refreshMe()).rejects.toMatchObject({ code: 'session_expired' });
    expect(handler).toHaveBeenCalledTimes(1);
    expect(auth.isAuthenticated).toBe(false);
  });

  it('changePassword 成功后清除强制改密标记', async () => {
    setActivePinia(createPinia());
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => jsonResponse({ ok: true })),
    );
    const auth = useAuthStore();
    auth.mustChangePassword = true;
    await auth.changePassword({ current_password: 'old', new_password: 'new-password-123' });
    expect(auth.mustChangePassword).toBe(false);
  });

  it('reauthenticate 记录服务端复验有效期', async () => {
    setActivePinia(createPinia());
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => jsonResponse({ reauthenticated_until: '2026-09-01T09:00:00Z' })),
    );
    const auth = useAuthStore();
    const until = await auth.reauthenticate('password');
    expect(until).toBe('2026-09-01T09:00:00Z');
    expect(auth.reauthenticatedUntil).toBe('2026-09-01T09:00:00Z');
  });
});
