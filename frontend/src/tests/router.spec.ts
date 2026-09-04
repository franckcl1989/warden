import { createPinia, setActivePinia } from 'pinia';
import { mount } from '@vue/test-utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createMemoryHistory } from 'vue-router';

import App from '@/App.vue';
import { createAppRouter, routes } from '@/router';
import { useAuthStore } from '@/stores/auth';

// PRODUCT_DESIGN §2 信息架构的 11 个页面 + 强制改密流程页 /change-password
// + 操作任务详情 /operations/:id（M2T7）
const EXPECTED_PATHS = [
  '/login',
  '/change-password',
  '/overview',
  '/devices',
  '/devices/new',
  '/devices/:id',
  '/alerts',
  '/operations',
  '/operations/:id',
  '/files',
  '/audit',
  '/users',
  '/system',
  '/terminal/sessions/:ticket',
];

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function userView(role: 'admin' | 'operator' | 'viewer', mustChangePassword = false) {
  return {
    id: 'u-1',
    username: role,
    display_name: role,
    role,
    status: 'active',
    must_change_password: mustChangePassword,
    last_login_at: null,
    created_at: '2026-09-01T00:00:00Z',
    updated_at: '2026-09-01T00:00:00Z',
    version: 1,
  };
}

function meResponse(role: 'admin' | 'operator' | 'viewer', mustChangePassword = false) {
  return {
    user: userView(role, mustChangePassword),
    permissions: ['device.read'],
    session_expires_at: '2026-09-02T00:00:00Z',
  };
}

describe('router 路由表', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('包含 PRODUCT_DESIGN §2 的 11 个路由、强制改密页及任务详情页，路径精确匹配', () => {
    const paths = routes.map((route) => route.path).sort();
    expect(paths).toEqual([...EXPECTED_PATHS].sort());
    expect(routes).toHaveLength(14);
  });

  it('每个路由都有名称、中文标题和组件', () => {
    for (const route of routes) {
      expect(route.name).toBeTypeOf('string');
      expect(route.meta?.title).toBeTypeOf('string');
      expect(route.component).toBeDefined();
    }
  });

  it('未登录访问受保护页重定向到 /login 并携带 next', async () => {
    setActivePinia(createPinia());
    const router = createAppRouter(createMemoryHistory());
    await router.push('/devices');
    expect(router.currentRoute.value.name).toBe('login');
    expect(router.currentRoute.value.query.next).toBe('/devices');
  });

  it('会话 Cookie 有效时守卫通过 me() 恢复登录态', async () => {
    setActivePinia(createPinia());
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              user: userView('admin'),
              permissions: ['device.read', 'device.manage', 'user.manage'],
              session_expires_at: '2026-09-02T00:00:00Z',
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          ),
      ),
    );
    const router = createAppRouter(createMemoryHistory());
    await router.push('/devices');
    expect(router.currentRoute.value.name).toBe('devices');
    const auth = useAuthStore();
    expect(auth.user?.username).toBe('admin');
  });

  it('me() 返回 session_expired 时回到登录页', async () => {
    setActivePinia(createPinia());
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              error: {
                code: 'session_expired',
                message: '会话已过期',
                details: {},
                request_id: 'r',
              },
            }),
            { status: 401, headers: { 'content-type': 'application/json' } },
          ),
      ),
    );
    const router = createAppRouter(createMemoryHistory());
    await router.push('/devices');
    expect(router.currentRoute.value.name).toBe('login');
    expect(router.currentRoute.value.query.next).toBe('/devices');
  });

  it('已登录访问 /login 回到总览', async () => {
    setActivePinia(createPinia());
    const auth = useAuthStore();
    auth.user = userView('admin');
    auth.permissions = ['device.read'];
    const router = createAppRouter(createMemoryHistory());
    await router.push('/login');
    expect(router.currentRoute.value.name).toBe('overview');
  });

  it('运维员访问管理员专属 /users 被拦截回总览', async () => {
    setActivePinia(createPinia());
    const auth = useAuthStore();
    auth.user = userView('operator');
    auth.permissions = ['device.read'];
    const router = createAppRouter(createMemoryHistory());
    await router.push('/users');
    expect(router.currentRoute.value.name).toBe('overview');
  });

  it('管理员可以进入 /users', async () => {
    setActivePinia(createPinia());
    const auth = useAuthStore();
    auth.user = userView('admin');
    auth.permissions = ['user.manage'];
    const router = createAppRouter(createMemoryHistory());
    await router.push('/users');
    expect(router.currentRoute.value.name).toBe('users');
  });

  it('刷新恢复的强制改密会话被引导到 /change-password 并携带 next', async () => {
    setActivePinia(createPinia());
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => jsonResponse(meResponse('viewer', true))),
    );
    const router = createAppRouter(createMemoryHistory());
    await router.push('/devices');
    expect(router.currentRoute.value.name).toBe('change-password');
    expect(router.currentRoute.value.query.next).toBe('/devices');
    expect(useAuthStore().mustChangePassword).toBe(true);
  });

  it('强制改密会话改密后导航继续进入目标页', async () => {
    setActivePinia(createPinia());
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (String(url).endsWith('/auth/password')) {
          return jsonResponse({ ok: true });
        }
        return jsonResponse(meResponse('admin', true));
      }),
    );
    const router = createAppRouter(createMemoryHistory());
    await router.push('/devices');
    expect(router.currentRoute.value.name).toBe('change-password');
    const auth = useAuthStore();
    await auth.changePassword({
      current_password: 'Old-Pass-2026!',
      new_password: 'Br@nd-New-2026-Pass',
    });
    expect(auth.mustChangePassword).toBe(false);
    await router.push('/devices');
    expect(router.currentRoute.value.name).toBe('devices');
  });

  it('已改密会话直接访问 /change-password 回到总览', async () => {
    setActivePinia(createPinia());
    const auth = useAuthStore();
    auth.user = userView('admin');
    auth.permissions = ['device.read'];
    const router = createAppRouter(createMemoryHistory());
    await router.push('/change-password');
    expect(router.currentRoute.value.name).toBe('overview');
  });

  it('未登录访问 /change-password 回登录页并携带 next', async () => {
    setActivePinia(createPinia());
    const router = createAppRouter(createMemoryHistory());
    await router.push('/change-password');
    expect(router.currentRoute.value.name).toBe('login');
    expect(router.currentRoute.value.query.next).toBe('/change-password');
  });

  it('强制改密用户访问 /login 被引导到改密页', async () => {
    setActivePinia(createPinia());
    const auth = useAuthStore();
    auth.user = userView('viewer', true);
    auth.mustChangePassword = true;
    auth.permissions = ['device.read'];
    const router = createAppRouter(createMemoryHistory());
    await router.push('/login');
    expect(router.currentRoute.value.name).toBe('change-password');
  });

  it('API 返回 password_change_required 时重定向到改密页并同步状态', async () => {
    const pinia = createPinia();
    setActivePinia(pinia);
    const auth = useAuthStore();
    auth.user = userView('viewer');
    auth.permissions = ['device.read'];
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse(
          {
            error: {
              code: 'permission_denied',
              message: '需要先修改密码',
              details: { permission: 'password_change_required' },
              request_id: 'r-1',
            },
          },
          403,
        ),
      ),
    );
    const router = createAppRouter(createMemoryHistory());
    await router.push('/devices');
    await router.isReady();
    // 挂载 App 渲染 RouterView，让设备列表页真正发起请求并触发 403 处理槽
    mount(App, { global: { plugins: [pinia, router] } });
    await vi.waitFor(() => {
      expect(router.currentRoute.value.name).toBe('change-password');
    });
    expect(router.currentRoute.value.query.next).toBe('/devices');
    expect(auth.mustChangePassword).toBe(true);
  });
});
