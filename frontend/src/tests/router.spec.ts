import { createPinia, setActivePinia } from 'pinia';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createMemoryHistory } from 'vue-router';

import { createAppRouter, routes } from '@/router';
import { useAuthStore } from '@/stores/auth';

// PRODUCT_DESIGN §2 信息架构的 11 个页面路由
const EXPECTED_PATHS = [
  '/login',
  '/overview',
  '/devices',
  '/devices/new',
  '/devices/:id',
  '/alerts',
  '/operations',
  '/files',
  '/audit',
  '/users',
  '/system',
];

function userView(role: 'admin' | 'operator' | 'viewer') {
  return {
    id: 'u-1',
    username: role,
    display_name: role,
    role,
    status: 'active',
    must_change_password: false,
    last_login_at: null,
    created_at: '2026-09-01T00:00:00Z',
    updated_at: '2026-09-01T00:00:00Z',
    version: 1,
  };
}

describe('router 路由表', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('包含 PRODUCT_DESIGN §2 的 11 个路由且路径精确匹配', () => {
    const paths = routes.map((route) => route.path).sort();
    expect(paths).toEqual([...EXPECTED_PATHS].sort());
    expect(routes).toHaveLength(11);
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
});
