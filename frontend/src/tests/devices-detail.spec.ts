import { createPinia, setActivePinia } from 'pinia';
import { mount } from '@vue/test-utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createMemoryHistory } from 'vue-router';

import DevicesDetailView from '@/features/devices/DevicesDetailView.vue';
import { createAppRouter } from '@/router';
import { useAuthStore } from '@/stores/auth';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function deviceView(extra: Record<string, unknown> = {}) {
  return {
    id: 'd-1',
    name: 'server-01',
    device_type: 'server',
    vendor: 'Fake',
    model: 'FakeServer-1',
    management_endpoint: '10.0.0.1',
    adapter_key: 'fake.simple',
    connection_config: { protocol: 'https', port: 443, verify_tls: true },
    enabled: true,
    readiness: 'ready',
    reachability: 'online',
    health: 'healthy',
    last_known_health: null,
    serial_number: 'SN-1',
    firmware_version: '1.0.0',
    last_seen_at: '2026-09-01T08:00:00Z',
    last_collected_at: null,
    next_poll_at: null,
    consecutive_failures: 0,
    consecutive_successes: 1,
    version: 3,
    created_at: '2026-09-01T00:00:00Z',
    updated_at: '2026-09-01T08:00:00Z',
    ...extra,
  };
}

const CAPABILITIES = {
  items: [
    {
      capability_key: 'health.overall',
      requirement_id: 'SRV-MON-01',
      requirement_title: '整机综合健康状态与告警灯',
      support_state: 'supported',
      discovery_method: 'fake.simple',
      reason_code: null,
      detail: null,
      last_checked_at: '2026-09-01T08:00:00Z',
      adapter_version: '0.1.0',
    },
    {
      capability_key: 'console.kvm.open',
      requirement_id: 'SRV-ACT-03',
      requirement_title: '远程 KVM 控制台连接',
      support_state: 'unsupported',
      discovery_method: 'fake.simple',
      reason_code: 'model_unsupported',
      detail: '该型号固件不支持 KVM 功能',
      last_checked_at: '2026-09-01T08:00:00Z',
      adapter_version: '0.1.0',
    },
  ],
};

async function flushAll(): Promise<void> {
  for (let i = 0; i < 3; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

async function mountDetail() {
  const pinia = createPinia();
  setActivePinia(pinia);
  const auth = useAuthStore();
  auth.user = {
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
  auth.permissions = ['device.read', 'device.manage', 'user.manage'];
  const router = createAppRouter(createMemoryHistory());
  await router.push('/devices/d-1');
  await router.isReady();
  const wrapper = mount(DevicesDetailView, {
    global: { plugins: [pinia, router] },
  });
  return { wrapper, router };
}

describe('设备详情（PLT-02）', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('头部展示身份、可达性/健康徽标与启用状态', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (String(url).includes('/capabilities')) return jsonResponse(CAPABILITIES);
        return jsonResponse(deviceView());
      }),
    );
    const { wrapper } = await mountDetail();
    await flushAll();
    expect(wrapper.text()).toContain('server-01');
    expect(wrapper.text()).toContain('10.0.0.1');
    expect(wrapper.text()).toContain('在线');
    expect(wrapper.text()).toContain('健康');
    expect(wrapper.text()).toContain('已启用');
    expect(wrapper.text()).toContain('SN-1');
  });

  it('能力清单渲染支持状态与原因', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (String(url).includes('/capabilities')) return jsonResponse(CAPABILITIES);
        return jsonResponse(deviceView());
      }),
    );
    const { wrapper } = await mountDetail();
    await flushAll();
    expect(wrapper.text()).toContain('SRV-MON-01');
    expect(wrapper.text()).toContain('health.overall');
    expect(wrapper.text()).toContain('支持');
    expect(wrapper.text()).toContain('SRV-ACT-03');
    expect(wrapper.text()).toContain('console.kvm.open');
    expect(wrapper.text()).toContain('不支持');
  });

  it('编辑时修改管理地址触发重新探测门禁', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (String(url).includes('/capabilities')) return jsonResponse(CAPABILITIES);
        return jsonResponse(deviceView());
      }),
    );
    const { wrapper } = await mountDetail();
    await flushAll();
    await wrapper.get('[data-testid="edit-device"]').trigger('click');
    await wrapper.vm.$nextTick();
    expect(wrapper.find('[data-testid="reprobe-gate"]').exists()).toBe(false);
    await wrapper.get('input[data-testid="edit-endpoint"]').setValue('10.0.0.9');
    await wrapper.vm.$nextTick();
    expect(wrapper.get('[data-testid="reprobe-gate"]').text()).toContain(
      '连接配置或凭据已修改，保存前必须重新连接测试',
    );
    expect(wrapper.get('[data-testid="save-edit"]').attributes('disabled')).toBeDefined();
  });

  it('仅修改名称时不需要重新探测，保存携带 If-Match', async () => {
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      void init;
      if (String(url).includes('/capabilities')) return jsonResponse(CAPABILITIES);
      if (String(url).includes('/devices/d-1')) {
        return jsonResponse(deviceView({ name: 'server-01-new' }));
      }
      return jsonResponse(deviceView());
    });
    vi.stubGlobal('fetch', fetchMock);
    const { wrapper } = await mountDetail();
    await flushAll();
    await wrapper.get('[data-testid="edit-device"]').trigger('click');
    await wrapper.vm.$nextTick();
    await wrapper.get('input[data-testid="edit-name"]').setValue('server-01-new');
    await wrapper.vm.$nextTick();
    expect(wrapper.find('[data-testid="reprobe-gate"]').exists()).toBe(false);
    await wrapper.get('[data-testid="save-edit"]').trigger('click');
    await flushAll();
    const patchCall = fetchMock.mock.calls.find(
      (call) => call[1]?.method === 'PATCH',
    ) as unknown as [string, RequestInit];
    expect(patchCall).toBeDefined();
    expect(patchCall[1].headers).toMatchObject({ 'If-Match': '3' });
    const body = JSON.parse(String(patchCall[1].body)) as Record<string, unknown>;
    expect(body).toEqual({ name: 'server-01-new' });
  });
});
