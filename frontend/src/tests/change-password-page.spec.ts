import { createPinia, setActivePinia } from 'pinia';
import { mount } from '@vue/test-utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createMemoryHistory } from 'vue-router';

import ChangePasswordPage from '@/features/login/ChangePasswordPage.vue';
import { createAppRouter } from '@/router';
import { useAuthStore } from '@/stores/auth';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function userView(mustChangePassword: boolean) {
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

async function flushAll(): Promise<void> {
  for (let i = 0; i < 3; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

async function mountPage(next: string | undefined) {
  const pinia = createPinia();
  setActivePinia(pinia);
  const auth = useAuthStore();
  auth.user = userView(true);
  auth.permissions = ['device.read'];
  auth.mustChangePassword = true;
  const router = createAppRouter(createMemoryHistory());
  await router.push({ path: '/change-password', query: next ? { next } : {} });
  await router.isReady();
  const wrapper = mount(ChangePasswordPage, {
    global: { plugins: [pinia, router] },
  });
  return { wrapper, router, auth };
}

async function fillChangeForm(wrapper: Awaited<ReturnType<typeof mountPage>>['wrapper']) {
  await wrapper.get('input[autocomplete="current-password"]').setValue('Old-Pass-2026!');
  const newPasswordInputs = wrapper.findAll('input[autocomplete="new-password"]');
  await newPasswordInputs[0]!.setValue('Br@nd-New-2026-Pass');
  await newPasswordInputs[1]!.setValue('Br@nd-New-2026-Pass');
}

describe('强制改密页（SECURITY §2，会话恢复引导）', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('渲染改密面板', async () => {
    const { wrapper } = await mountPage(undefined);
    expect(wrapper.text()).toContain('首次登录需修改密码');
  });

  it('改密成功后跳转到 next 目标', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (String(url).endsWith('/auth/password')) {
          return jsonResponse({ ok: true });
        }
        return jsonResponse(
          { error: { code: 'unauthenticated', message: '未登录', details: {}, request_id: 'r' } },
          401,
        );
      }),
    );
    const { wrapper, router, auth } = await mountPage('/devices');
    await fillChangeForm(wrapper);
    const submitButton = wrapper
      .findAll('button')
      .find((button) => button.text().includes('确认修改'));
    expect(submitButton).toBeDefined();
    await submitButton!.trigger('click');
    await flushAll();
    await vi.waitFor(() => {
      expect(router.currentRoute.value.name).toBe('devices');
    });
    expect(auth.mustChangePassword).toBe(false);
  });

  it('退出登录回到登录页', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (String(url).endsWith('/auth/logout')) {
          return jsonResponse({ ok: true });
        }
        return jsonResponse(
          { error: { code: 'unauthenticated', message: '未登录', details: {}, request_id: 'r' } },
          401,
        );
      }),
    );
    const { wrapper, router } = await mountPage('/devices');
    await wrapper.get('[data-testid="change-password-logout"]').trigger('click');
    await flushAll();
    await vi.waitFor(() => {
      expect(router.currentRoute.value.name).toBe('login');
    });
  });
});
