import { createPinia, setActivePinia } from 'pinia';
import { mount } from '@vue/test-utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createMemoryHistory } from 'vue-router';

import LoginPage from '@/features/login/LoginPage.vue';
import { createAppRouter } from '@/router';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function userView(mustChangePassword = false) {
  return {
    id: 'u-1',
    username: 'admin',
    display_name: '管理员',
    role: 'admin',
    status: 'active',
    must_change_password: mustChangePassword,
    last_login_at: null,
    created_at: '2026-09-01T00:00:00Z',
    updated_at: '2026-09-01T00:00:00Z',
    version: 1,
  };
}

/** 未登录时守卫会调用 /auth/me；统一以 401 应答，避免真实网络请求。 */
function stubUnauthenticated() {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () =>
      jsonResponse(
        { error: { code: 'unauthenticated', message: '未登录', details: {}, request_id: 'r' } },
        401,
      ),
    ),
  );
}

async function flushAll(): Promise<void> {
  for (let i = 0; i < 3; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

async function mountLogin() {
  const pinia = createPinia();
  setActivePinia(pinia);
  const router = createAppRouter(createMemoryHistory());
  await router.push('/login');
  await router.isReady();
  const wrapper = mount(LoginPage, {
    global: { plugins: [pinia, router] },
  });
  return { wrapper, router };
}

async function fillForm(wrapper: Awaited<ReturnType<typeof mountLogin>>['wrapper']) {
  await wrapper.get('input[data-testid="username"]').setValue('admin');
  await wrapper.get('input[data-testid="password"]').setValue('password-123');
}

describe('登录页（PLT-01）', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('渲染用户名/密码表单', async () => {
    stubUnauthenticated();
    const { wrapper } = await mountLogin();
    expect(wrapper.find('input[data-testid="username"]').exists()).toBe(true);
    expect(wrapper.find('input[data-testid="password"]').exists()).toBe(true);
    expect(wrapper.get('[data-testid="login-submit"]').text()).toContain('登');
  });

  it('提交调用登录并跳转到 next 目标', async () => {
    const pinia = createPinia();
    setActivePinia(pinia);
    // 守卫的 /auth/me 先返回 401，登录接口返回成功
    const fetchMock = vi.fn(async (url: string) => {
      if (String(url).endsWith('/auth/me')) {
        return jsonResponse(
          { error: { code: 'unauthenticated', message: '未登录', details: {}, request_id: 'r' } },
          401,
        );
      }
      return jsonResponse({
        user: userView(false),
        csrf_token: 'csrf-1',
        session_expires_at: '2026-09-03T00:00:00Z',
      });
    });
    vi.stubGlobal('fetch', fetchMock);
    const router = createAppRouter(createMemoryHistory());
    await router.push({ name: 'login', query: { next: '/devices' } });
    await router.isReady();
    const wrapper = mount(LoginPage, {
      global: { plugins: [pinia, router] },
    });
    await fillForm(wrapper);
    await wrapper.get('[data-testid="login-submit"]').trigger('click');
    await flushAll();
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(init.method).toBe('POST');
    expect(init.body).toBe(JSON.stringify({ username: 'admin', password: 'password-123' }));
    await vi.waitFor(() => {
      expect(router.currentRoute.value.name).toBe('devices');
    });
  });

  it('登录失败显示错误码与请求 ID', async () => {
    const pinia = createPinia();
    setActivePinia(pinia);
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (String(url).endsWith('/auth/me')) {
          return jsonResponse(
            { error: { code: 'unauthenticated', message: '未登录', details: {}, request_id: 'r' } },
            401,
          );
        }
        return jsonResponse(
          {
            error: {
              code: 'validation_failed',
              message: '用户名或密码错误',
              details: { field: 'password', reason: 'invalid_credentials' },
              request_id: 'req-login-1',
            },
          },
          422,
        );
      }),
    );
    const { wrapper } = await mountLogin();
    await fillForm(wrapper);
    await wrapper.get('[data-testid="login-submit"]').trigger('click');
    await flushAll();
    expect(wrapper.text()).toContain('用户名或密码错误');
    expect(wrapper.text()).toContain('validation_failed');
    expect(wrapper.text()).toContain('req-login-1');
  });

  it('must_change_password 时强制进入改密视图', async () => {
    const pinia = createPinia();
    setActivePinia(pinia);
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (String(url).endsWith('/auth/me')) {
          return jsonResponse(
            { error: { code: 'unauthenticated', message: '未登录', details: {}, request_id: 'r' } },
            401,
          );
        }
        return jsonResponse({
          user: userView(true),
          csrf_token: 'csrf-1',
          session_expires_at: '2026-09-03T00:00:00Z',
        });
      }),
    );
    const { wrapper } = await mountLogin();
    await fillForm(wrapper);
    await wrapper.get('[data-testid="login-submit"]').trigger('click');
    await flushAll();
    expect(wrapper.text()).toContain('首次登录需修改密码');
  });
});
