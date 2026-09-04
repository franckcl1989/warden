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

/** 直接以 URL 页签深链打开详情（页签写入 URL query，UI_SPEC §2）。 */
async function mountDetailAt(path: string) {
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
  await router.push(path);
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

  it('概览“当前问题”为空时显示空态，与加载/无权限/错误区分（M6T1）', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        const u = String(url);
        if (u.includes('/capabilities')) return jsonResponse(CAPABILITIES);
        if (u.includes('/metrics/latest')) {
          return jsonResponse({ items: [], page: 1, page_size: 100, total: 0 });
        }
        if (u.includes('/alerts?')) {
          return jsonResponse({ items: [], page: 1, page_size: 50, total: 0 });
        }
        return jsonResponse(deviceView());
      }),
    );
    const { wrapper } = await mountDetail();
    await flushAll();
    expect(wrapper.text()).toContain('当前无未恢复问题');
    // 加载完成态下不出现错误/无权限文案
    expect(wrapper.text()).not.toContain('无权限查看该页面');
  });

  it('指标页签区分 unsupported/unknown(尚无观测)/expired（M6T1，UI_SPEC §7.3）', async () => {
    const caps = {
      items: [
        ...CAPABILITIES.items,
        {
          capability_key: 'temperature.cpu',
          requirement_id: 'SRV-MON-02',
          requirement_title: 'CPU 温度',
          support_state: 'supported',
          discovery_method: 'fake.simple',
          reason_code: null,
          detail: null,
          last_checked_at: '2026-09-01T08:00:00Z',
          adapter_version: '0.1.0',
        },
        {
          capability_key: 'temperature.memory',
          requirement_id: 'SRV-MON-02',
          requirement_title: '内存温度',
          support_state: 'unsupported',
          discovery_method: 'fake.simple',
          reason_code: 'model_unsupported',
          detail: '该型号固件无内存温度读数',
          last_checked_at: '2026-09-01T08:00:00Z',
          adapter_version: '0.1.0',
        },
      ],
    };
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        const u = String(url);
        if (u.includes('/capabilities')) return jsonResponse(caps);
        if (u.includes('/metrics/latest')) {
          return jsonResponse({
            items: [
              {
                component: {
                  id: 'c-1',
                  kind: 'sensor',
                  native_id: 'CPU1 Temp',
                  name: 'CPU1 温度',
                },
                metrics: [
                  {
                    metric_key: 'temperature.cpu',
                    value: 55.2,
                    unit: 'Cel',
                    quality: 'good',
                    observed_at: '2026-09-01T08:00:00Z',
                    source: 'poll',
                    freshness: 'expired',
                  },
                ],
              },
            ],
            page: 1,
            page_size: 100,
            total: 1,
          });
        }
        if (u.includes('/alerts?')) {
          return jsonResponse({ items: [], page: 1, page_size: 50, total: 0 });
        }
        return jsonResponse(deviceView());
      }),
    );
    const { wrapper } = await mountDetailAt('/devices/d-1?tab=metrics');
    await flushAll();
    const text = wrapper.text();
    // 过期观测：值 + “已过期”，不清零也不伪装成无数据
    expect(text).toContain('已过期');
    expect(text).toContain('55.2');
    // 受支持但尚无观测：明确“尚无观测数据”，与过期分离
    expect(text).toContain('尚无观测数据（受支持指标尚未产生一次成功观测）');
    // 不支持：显示设备原因，不与任何“暂无”混淆
    expect(text).toContain('该型号固件无内存温度读数');
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

  it('connection_config 缺省端口/协议/校验键时按适配器默认值比较，不误触发重新探测', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (String(url).includes('/capabilities')) return jsonResponse(CAPABILITIES);
        return jsonResponse(
          deviceView({ connection_config: { protocol: 'https', verify_tls: true } }),
        );
      }),
    );
    const { wrapper } = await mountDetail();
    await flushAll();
    await wrapper.get('[data-testid="edit-device"]').trigger('click');
    await wrapper.vm.$nextTick();
    expect(wrapper.find('[data-testid="reprobe-gate"]').exists()).toBe(false);
  });

  it('清空 TLS 指纹后，探测与保存载荷都从 connection_config 移除该键', async () => {
    const FINGERPRINT = 'a'.repeat(64);
    const STORED_DEVICE = deviceView({
      connection_config: {
        protocol: 'https',
        port: 443,
        verify_tls: true,
        tls_fingerprint_sha256: FINGERPRINT,
      },
    });
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      void init;
      if (String(url).includes('/capabilities')) return jsonResponse(CAPABILITIES);
      if (String(url).endsWith('/device-probes')) {
        return jsonResponse({
          ok: true,
          stages: [
            { stage: 'network', ok: true, error_code: null, detail: null },
            { stage: 'tls', ok: true, error_code: null, detail: null },
            { stage: 'auth', ok: true, error_code: null, detail: null },
            { stage: 'identity', ok: true, error_code: null, detail: null },
            { stage: 'capabilities', ok: true, error_code: null, detail: null },
          ],
          discovery: null,
          probe_token: 'token-ok',
          expires_at: '2026-09-01T08:10:00Z',
        });
      }
      if (String(url).includes('/devices/d-1')) {
        return jsonResponse(STORED_DEVICE);
      }
      return jsonResponse(STORED_DEVICE);
    });
    vi.stubGlobal('fetch', fetchMock);
    const { wrapper } = await mountDetail();
    await flushAll();
    await wrapper.get('[data-testid="edit-device"]').trigger('click');
    await wrapper.vm.$nextTick();
    const fingerprintInput = wrapper.get('input[placeholder^="SHA-256"]');
    expect((fingerprintInput.element as HTMLInputElement).value).toBe(FINGERPRINT);
    await fingerprintInput.setValue('');
    await wrapper.vm.$nextTick();
    expect(wrapper.find('[data-testid="reprobe-gate"]').exists()).toBe(true);
    await wrapper.get('[data-testid="edit-run-probe"]').trigger('click');
    await flushAll();
    const probeCall = fetchMock.mock.calls.find((call) =>
      String(call[0]).endsWith('/device-probes'),
    ) as unknown as [string, RequestInit];
    expect(probeCall).toBeDefined();
    const probeBody = JSON.parse(String(probeCall[1].body)) as Record<string, unknown>;
    expect(
      (probeBody['connection_config'] as Record<string, unknown>)['tls_fingerprint_sha256'],
    ).toBeUndefined();
    await wrapper.get('[data-testid="save-edit"]').trigger('click');
    await flushAll();
    const patchCall = fetchMock.mock.calls.find(
      (call) => call[1]?.method === 'PATCH',
    ) as unknown as [string, RequestInit];
    expect(patchCall).toBeDefined();
    const patchBody = JSON.parse(String(patchCall[1].body)) as Record<string, unknown>;
    expect(
      (patchBody['connection_config'] as Record<string, unknown>)['tls_fingerprint_sha256'],
    ).toBeUndefined();
  });

  it('关闭 TLS 校验后，探测载荷不携带残留的 TLS 指纹', async () => {
    const FINGERPRINT = 'b'.repeat(64);
    const fetchMock = vi.fn(async (url: string) => {
      if (String(url).includes('/capabilities')) return jsonResponse(CAPABILITIES);
      if (String(url).endsWith('/device-probes')) {
        return jsonResponse({
          ok: true,
          stages: [
            { stage: 'network', ok: true, error_code: null, detail: null },
            { stage: 'tls', ok: true, error_code: null, detail: null },
            { stage: 'auth', ok: true, error_code: null, detail: null },
            { stage: 'identity', ok: true, error_code: null, detail: null },
            { stage: 'capabilities', ok: true, error_code: null, detail: null },
          ],
          discovery: null,
          probe_token: 'token-ok',
          expires_at: '2026-09-01T08:10:00Z',
        });
      }
      return jsonResponse(
        deviceView({
          connection_config: {
            protocol: 'https',
            port: 443,
            verify_tls: true,
            tls_fingerprint_sha256: FINGERPRINT,
          },
        }),
      );
    });
    vi.stubGlobal('fetch', fetchMock);
    const { wrapper } = await mountDetail();
    await flushAll();
    await wrapper.get('[data-testid="edit-device"]').trigger('click');
    await wrapper.vm.$nextTick();
    const checkbox = wrapper.findComponent({ name: 'ElCheckbox' });
    checkbox.vm.$emit('update:modelValue', false);
    await wrapper.vm.$nextTick();
    expect(wrapper.find('input[placeholder^="SHA-256"]').exists()).toBe(false);
    await wrapper.get('[data-testid="edit-run-probe"]').trigger('click');
    await flushAll();
    const probeCall = fetchMock.mock.calls.find((call) =>
      String(call[0]).endsWith('/device-probes'),
    ) as unknown as [string, RequestInit];
    expect(probeCall).toBeDefined();
    const probeBody = JSON.parse(String(probeCall[1].body)) as Record<string, unknown>;
    const config = probeBody['connection_config'] as Record<string, unknown>;
    expect(config['verify_tls']).toBe(false);
    expect(config['tls_fingerprint_sha256']).toBeUndefined();
  });
});
