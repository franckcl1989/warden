import { createPinia, setActivePinia } from 'pinia';
import { mount } from '@vue/test-utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createMemoryHistory } from 'vue-router';

import UsersPage from '@/features/users/UsersPage.vue';
import { createAppRouter } from '@/router';
import { useAuthStore } from '@/stores/auth';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function userRow(username: string, role = 'viewer', status = 'active') {
  return {
    id: `u-${username}`,
    username,
    display_name: username,
    role,
    status,
    must_change_password: false,
    last_login_at: '2026-09-01T08:00:00Z',
    created_at: '2026-09-01T00:00:00Z',
    updated_at: '2026-09-01T00:00:00Z',
    version: 1,
  };
}

function seedUser(role: 'admin' | 'operator' | 'viewer') {
  const auth = useAuthStore();
  auth.user = userRow(role, role);
  auth.permissions = role === 'admin' ? ['user.manage'] : ['device.read'];
}

async function flushAll(): Promise<void> {
  for (let i = 0; i < 3; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

async function mountUsers(role: 'admin' | 'operator' | 'viewer') {
  const pinia = createPinia();
  setActivePinia(pinia);
  seedUser(role);
  const router = createAppRouter(createMemoryHistory());
  await router.push('/users');
  await router.isReady();
  const wrapper = mount(UsersPage, {
    global: { plugins: [pinia, router] },
  });
  return { wrapper, router };
}

describe('用户与角色页（PLT-01，仅管理员）', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('非管理员渲染无权限状态', async () => {
    const { wrapper } = await mountUsers('operator');
    await flushAll();
    expect(wrapper.text()).toContain('无权限查看该页面');
  });

  it('管理员渲染用户表格', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse({
          items: [userRow('admin', 'admin'), userRow('op1', 'operator')],
          page: 1,
          page_size: 20,
          total: 2,
        }),
      ),
    );
    const { wrapper } = await mountUsers('admin');
    await flushAll();
    expect(wrapper.text()).toContain('admin');
    expect(wrapper.text()).toContain('op1');
    expect(wrapper.text()).toContain('管理员');
    expect(wrapper.text()).toContain('运维员');
  });

  it('创建用户调用 POST /users', async () => {
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      void init;
      if (String(url).includes('/users?page')) {
        return jsonResponse({ items: [], page: 1, page_size: 20, total: 0 });
      }
      return jsonResponse(userRow('newbie'), 201);
    });
    vi.stubGlobal('fetch', fetchMock);
    const { wrapper } = await mountUsers('admin');
    await flushAll();
    await wrapper.get('[data-testid="create-user"]').trigger('click');
    await wrapper.vm.$nextTick();
    await wrapper.get('input[data-testid="new-username"]').setValue('newbie');
    await wrapper.get('input[data-testid="new-display-name"]').setValue('新人');
    await wrapper.get('input[data-testid="new-password"]').setValue('secure-password-123');
    await wrapper.get('input[data-testid="new-confirm-password"]').setValue('secure-password-123');
    await wrapper.vm.$nextTick();
    await wrapper.get('[data-testid="confirm-create"]').trigger('click');
    await flushAll();
    const postCall = fetchMock.mock.calls.find((call) => call[1]?.method === 'POST') as unknown as [
      string,
      RequestInit,
    ];
    expect(postCall).toBeDefined();
    expect(postCall[0]).toBe('/api/v1/users');
    expect(JSON.parse(String(postCall[1].body))).toMatchObject({ username: 'newbie' });
  });

  it('管理员被 API 403 时显示无权限状态', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse(
          {
            error: { code: 'permission_denied', message: '权限不足', details: {}, request_id: 'r' },
          },
          403,
        ),
      ),
    );
    const { wrapper } = await mountUsers('admin');
    await flushAll();
    expect(wrapper.text()).toContain('无权限查看该页面');
  });
});
