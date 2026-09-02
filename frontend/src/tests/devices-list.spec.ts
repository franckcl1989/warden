import { createPinia, setActivePinia } from 'pinia';
import { mount } from '@vue/test-utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createMemoryHistory } from 'vue-router';

import DevicesListView from '@/features/devices/DevicesListView.vue';
import { createAppRouter } from '@/router';
import { useAuthStore } from '@/stores/auth';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function deviceRow(id: string, name: string, extra: Record<string, unknown> = {}) {
  return {
    id,
    name,
    device_type: 'server',
    vendor: 'Fake',
    model: 'FakeServer-1',
    management_endpoint: '10.0.0.1',
    adapter_key: 'fake.simple',
    connection_config: { protocol: 'https', port: 443 },
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
    version: 1,
    created_at: '2026-09-01T00:00:00Z',
    updated_at: '2026-09-01T00:00:00Z',
    ...extra,
  };
}

function listResponse(items: unknown[], total: number) {
  return { items, page: 1, page_size: 20, total };
}

function seedAdmin() {
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
}

async function mountList() {
  setActivePinia(createPinia());
  seedAdmin();
  const router = createAppRouter(createMemoryHistory());
  await router.push('/devices');
  await router.isReady();
  const wrapper = mount(DevicesListView, {
    global: { plugins: [createPinia(), router] },
  });
  await flushAll();
  return { wrapper, router };
}

async function flushAll(): Promise<void> {
  for (let i = 0; i < 3; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

describe('设备列表（PLT-02）', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('渲染服务端返回的设备行与徽标', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => jsonResponse(listResponse([deviceRow('d-1', 'server-01')], 1))),
    );
    const { wrapper } = await mountList();
    expect(wrapper.text()).toContain('server-01');
    expect(wrapper.text()).toContain('Fake');
    expect(wrapper.text()).toContain('10.0.0.1');
    expect(wrapper.text()).toContain('在线');
    expect(wrapper.text()).toContain('健康');
  });

  it('筛选条件以 query 参数调用 API', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(listResponse([], 0)));
    vi.stubGlobal('fetch', fetchMock);
    const { wrapper } = await mountList();
    await wrapper.get('input[data-testid="filter-name"]').setValue('server');
    await wrapper.get('input[data-testid="filter-name"]').trigger('keyup.enter');
    await flushAll();
    const [url] = fetchMock.mock.calls.at(-1) as unknown as [string];
    expect(url).toContain('name=server');
    expect(url).toContain('page=1');
  });

  it('类型与启用筛选同样进入 query', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(listResponse([], 0)));
    vi.stubGlobal('fetch', fetchMock);
    const { wrapper } = await mountList();
    const typeSelect = wrapper
      .get('[data-testid="filter-type"]')
      .findComponent({ name: 'ElSelect' });
    await typeSelect.vm.$emit('update:modelValue', 'server');
    await typeSelect.vm.$emit('change', 'server');
    const enabledSelect = wrapper
      .get('[data-testid="filter-enabled"]')
      .findComponent({ name: 'ElSelect' });
    await enabledSelect.vm.$emit('update:modelValue', false);
    await enabledSelect.vm.$emit('change', false);
    await flushAll();
    const url = (fetchMock.mock.calls.at(-1) as unknown as [string])[0];
    expect(url).toContain('device_type=server');
    expect(url).toContain('enabled=false');
  });

  it('无任何设备且无筛选时显示尚未添加', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => jsonResponse(listResponse([], 0))),
    );
    const { wrapper } = await mountList();
    expect(wrapper.text()).toContain('尚未添加设备');
  });

  it('筛选无结果时显示筛选无结果并可清除筛选', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(listResponse([], 0)));
    vi.stubGlobal('fetch', fetchMock);
    const { wrapper } = await mountList();
    await wrapper.get('input[data-testid="filter-name"]').setValue('nothing');
    await wrapper.get('input[data-testid="filter-name"]').trigger('keyup.enter');
    await flushAll();
    expect(wrapper.text()).toContain('筛选无结果');
    await wrapper.get('[data-testid="filter-reset"]').trigger('click');
    await flushAll();
    const url = (fetchMock.mock.calls.at(-1) as unknown as [string])[0];
    expect(url).not.toContain('name=');
  });

  it('API 返回 permission_denied 时显示无权限状态', async () => {
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
    const { wrapper } = await mountList();
    expect(wrapper.text()).toContain('无权限查看该页面');
  });
});
