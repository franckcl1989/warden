import { createPinia, setActivePinia } from 'pinia';
import { mount } from '@vue/test-utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createMemoryHistory } from 'vue-router';

import App from '@/App.vue';
import { createAppRouter } from '@/router';
import { useAuthStore } from '@/stores/auth';

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

describe('App 外壳', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('公开路由（/login）不渲染应用侧栏', async () => {
    const pinia = createPinia();
    setActivePinia(pinia);
    const router = createAppRouter(createMemoryHistory());
    await router.push('/login');
    await router.isReady();
    const wrapper = mount(App, {
      global: { plugins: [pinia, router] },
    });
    expect(wrapper.findComponent({ name: 'ElConfigProvider' }).exists()).toBe(true);
    expect(wrapper.text()).toContain('Warden');
    expect(wrapper.find('.app-shell').exists()).toBe(false);
  });

  it('已登录路由渲染应用外壳与页面标题', async () => {
    const pinia = createPinia();
    setActivePinia(pinia);
    const auth = useAuthStore();
    auth.user = userView('admin');
    auth.permissions = ['device.read', 'device.manage', 'user.manage'];
    const router = createAppRouter(createMemoryHistory());
    await router.push('/overview');
    await router.isReady();
    const wrapper = mount(App, {
      global: { plugins: [pinia, router] },
    });
    expect(wrapper.find('.app-shell').exists()).toBe(true);
    expect(wrapper.text()).toContain('总览');
    expect(wrapper.text()).toContain('管理员');
  });

  it('未登录访问受保护页被守卫重定向到登录页', async () => {
    const pinia = createPinia();
    setActivePinia(pinia);
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              error: { code: 'unauthenticated', message: '未登录', details: {}, request_id: 'r' },
            }),
            { status: 401, headers: { 'content-type': 'application/json' } },
          ),
      ),
    );
    const router = createAppRouter(createMemoryHistory());
    await router.push('/overview');
    await router.isReady();
    expect(router.currentRoute.value.name).toBe('login');
  });
});
