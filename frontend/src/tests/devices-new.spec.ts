import { createPinia, setActivePinia } from 'pinia';
import { mount } from '@vue/test-utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createMemoryHistory } from 'vue-router';

import DevicesNewView from '@/features/devices/DevicesNewView.vue';
import { createAppRouter } from '@/router';
import { useAuthStore } from '@/stores/auth';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function okStage(stage: string) {
  return { stage, ok: true, error_code: null, detail: null };
}

function failStage(stage: string, errorCode: string | null, detail: string | null) {
  return { stage, ok: false, error_code: errorCode, detail };
}

function allOkProbe() {
  return {
    ok: true,
    stages: [
      okStage('network'),
      okStage('tls'),
      okStage('auth'),
      okStage('identity'),
      okStage('capabilities'),
    ],
    discovery: {
      vendor: 'Fake',
      model: 'FakeServer-1',
      serial_number: 'FAKE-SN-0001',
      firmware_version: '1.0.0',
      capabilities: [
        {
          capability_key: 'health.overall',
          support_state: 'supported',
          requirement_id: 'SRV-MON-01',
          discovery_method: 'fake.simple',
          reason_code: null,
          detail: null,
        },
      ],
      components: [],
    },
    probe_token: 'token-ok',
    expires_at: '2026-09-01T08:10:00Z',
  };
}

function authFailProbe() {
  return {
    ok: false,
    stages: [
      okStage('network'),
      okStage('tls'),
      failStage('auth', 'authentication_failed', '模拟凭据认证失败'),
      failStage('identity', null, '前置阶段失败，未执行'),
      failStage('capabilities', null, '前置阶段失败，未执行'),
    ],
    discovery: null,
    probe_token: 'token-fail',
    expires_at: '2026-09-01T08:10:00Z',
  };
}

async function flushAll(): Promise<void> {
  for (let i = 0; i < 3; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

async function mountWizard() {
  const pinia = createPinia();
  setActivePinia(pinia);
  // 保存后跳转设备详情需要已登录；守卫因此跳过 /auth/me
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
  await router.push('/devices/new');
  await router.isReady();
  const wrapper = mount(DevicesNewView, {
    global: { plugins: [pinia, router] },
  });
  return { wrapper, router };
}

/** 走完步骤 1-3，进入连接测试步骤。 */
async function walkToProbeStep(wrapper: Awaited<ReturnType<typeof mountWizard>>['wrapper']) {
  await wrapper
    .get('[data-testid="device-type"]')
    .findComponent({ name: 'ElSelect' })
    .vm.$emit('update:modelValue', 'server');
  await wrapper.get('[data-testid="next-step"]').trigger('click');
  await wrapper.get('input[data-testid="device-name"]').setValue('server-01');
  await wrapper.get('input[data-testid="management-endpoint"]').setValue('10.0.0.5');
  await wrapper.get('[data-testid="next-step"]').trigger('click');
  await wrapper.get('input[data-testid="credential-username"]').setValue('admin');
  await wrapper.get('input[data-testid="credential-password"]').setValue('secret-123');
  await wrapper.get('[data-testid="next-step"]').trigger('click');
}

describe('添加设备向导（PLT-02）', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('不支持设备类别的适配器选择被禁用', async () => {
    const { wrapper } = await mountWizard();
    await wrapper
      .get('[data-testid="device-type"]')
      .findComponent({ name: 'ElSelect' })
      .vm.$emit('update:modelValue', 'core_switch');
    await wrapper.vm.$nextTick();
    expect(wrapper.text()).toContain('该类别暂无可用适配器');
    expect(wrapper.get('[data-testid="next-step"]').attributes('disabled')).toBeDefined();
  });

  it('服务器类别提供五个厂商管理卡适配器（真机认证待完成标签）', async () => {
    const { wrapper } = await mountWizard();
    await wrapper
      .get('[data-testid="device-type"]')
      .findComponent({ name: 'ElSelect' })
      .vm.$emit('update:modelValue', 'server');
    await wrapper.vm.$nextTick();
    // 打开适配器下拉：选项渲染在 teleport 的下拉面板中。
    await wrapper.get('[data-testid="adapter-key"] .el-select__wrapper').trigger('click');
    await flushAll();
    const bodyText = document.body.textContent ?? '';
    for (const label of [
      '测试适配器（开发用）',
      'Dell iDRAC（真机认证待完成）',
      'Inspur iBMC（真机认证待完成）',
      'xFusion iBMC（真机认证待完成）',
      'Lenovo XCC（真机认证待完成）',
      'Huawei iBMC（真机认证待完成）',
    ]) {
      expect(bodyText).toContain(label);
    }
    expect(bodyText).not.toContain('已认证');
  });

  it('选择厂商适配器后探测请求携带对应 adapter_key', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(allOkProbe()));
    vi.stubGlobal('fetch', fetchMock);
    const { wrapper } = await mountWizard();
    await wrapper
      .get('[data-testid="device-type"]')
      .findComponent({ name: 'ElSelect' })
      .vm.$emit('update:modelValue', 'server');
    await wrapper
      .get('[data-testid="adapter-key"]')
      .findComponent({ name: 'ElSelect' })
      .vm.$emit('update:modelValue', 'server.dell_idrac');
    await wrapper.vm.$nextTick();
    await wrapper.get('[data-testid="next-step"]').trigger('click');
    await wrapper.get('input[data-testid="device-name"]').setValue('server-01');
    await wrapper.get('input[data-testid="management-endpoint"]').setValue('10.0.0.5');
    await wrapper.get('[data-testid="next-step"]').trigger('click');
    await wrapper.get('input[data-testid="credential-username"]').setValue('admin');
    await wrapper.get('input[data-testid="credential-password"]').setValue('secret-123');
    await wrapper.get('[data-testid="next-step"]').trigger('click');
    await wrapper.get('[data-testid="run-probe"]').trigger('click');
    await flushAll();
    const probeCall = fetchMock.mock.calls[0] as unknown as [string, RequestInit] | undefined;
    expect(probeCall).toBeDefined();
    const body = JSON.parse(String(probeCall?.[1]?.body)) as Record<string, unknown>;
    expect(body['adapter_key']).toBe('server.dell_idrac');
  });

  it('连接测试全部通过时展示五阶段通过', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(allOkProbe()));
    vi.stubGlobal('fetch', fetchMock);
    const { wrapper } = await mountWizard();
    await walkToProbeStep(wrapper);
    await wrapper.get('[data-testid="run-probe"]').trigger('click');
    await flushAll();
    const probeCall = fetchMock.mock.calls[0] as unknown as [string, RequestInit] | undefined;
    expect(probeCall).toBeDefined();
    expect(probeCall?.[1]?.method).toBe('POST');
    expect(String(probeCall?.[0])).toContain('/device-probes');
    expect(wrapper.text()).toContain('网络可达');
    expect(wrapper.text()).toContain('TLS/协议握手');
    expect(wrapper.text()).toContain('认证');
    expect(wrapper.text()).toContain('身份识别');
    expect(wrapper.text()).toContain('能力发现');
    expect(wrapper.get('[data-testid="probe-stages"]').text()).not.toContain('失败');
  });

  it('认证阶段失败时展示失败与错误码，并允许保存为未就绪', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(authFailProbe()));
    vi.stubGlobal('fetch', fetchMock);
    const { wrapper } = await mountWizard();
    await walkToProbeStep(wrapper);
    await wrapper.get('[data-testid="run-probe"]').trigger('click');
    await flushAll();
    expect(wrapper.get('[data-testid="probe-stages"]').text()).toContain('认证');
    expect(wrapper.get('[data-testid="probe-stages"]').text()).toContain('失败');
    expect(wrapper.get('[data-testid="probe-stages"]').text()).toContain('authentication_failed');
    await wrapper.get('[data-testid="next-step"]').trigger('click');
    await wrapper.vm.$nextTick();
    expect(wrapper.find('[data-testid="probe-failed-notice"]').exists()).toBe(true);
    await wrapper.get('[data-testid="next-step"]').trigger('click');
    await wrapper.vm.$nextTick();
    expect(wrapper.text()).toContain('不会启用采集');
  });

  it('失败令牌保存为 enabled=false 并跳转详情页', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(authFailProbe()));
    vi.stubGlobal('fetch', fetchMock);
    const { wrapper, router } = await mountWizard();
    await walkToProbeStep(wrapper);
    await wrapper.get('[data-testid="run-probe"]').trigger('click');
    await flushAll();
    await wrapper.get('[data-testid="next-step"]').trigger('click');
    await wrapper.vm.$nextTick();
    await wrapper.get('[data-testid="next-step"]').trigger('click');
    await wrapper.vm.$nextTick();
    const saveMock = vi.fn(async () =>
      jsonResponse(
        {
          id: 'd-9',
          name: 'server-01',
          device_type: 'server',
          vendor: null,
          model: null,
          management_endpoint: '10.0.0.5',
          adapter_key: 'fake.simple',
          connection_config: { protocol: 'https', port: 443 },
          enabled: false,
          readiness: 'not_ready',
          reachability: 'unknown',
          health: 'unknown',
          last_known_health: null,
          serial_number: null,
          firmware_version: null,
          last_seen_at: null,
          last_collected_at: null,
          next_poll_at: null,
          consecutive_failures: 0,
          consecutive_successes: 0,
          version: 1,
          created_at: '2026-09-01T00:00:00Z',
          updated_at: '2026-09-01T00:00:00Z',
        },
        201,
      ),
    );
    vi.stubGlobal('fetch', saveMock);
    await wrapper.get('[data-testid="save-device"]').trigger('click');
    await flushAll();
    const [, init] = saveMock.mock.calls[0] as unknown as [string, RequestInit];
    const body = JSON.parse(String(init.body)) as Record<string, unknown>;
    expect(body['enabled']).toBe(false);
    expect(body['probe_token']).toBe('token-fail');
    expect(router.currentRoute.value.name).toBe('device-detail');
    expect(router.currentRoute.value.params.id).toBe('d-9');
  });

  it('探测请求携带表单中的配置与凭据', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(allOkProbe()));
    vi.stubGlobal('fetch', fetchMock);
    const { wrapper } = await mountWizard();
    await walkToProbeStep(wrapper);
    await wrapper.get('[data-testid="run-probe"]').trigger('click');
    await flushAll();
    const probeCall = fetchMock.mock.calls[0] as unknown as [string, RequestInit] | undefined;
    expect(probeCall).toBeDefined();
    expect(String(probeCall?.[0])).toContain('/device-probes');
    const body = JSON.parse(String(probeCall?.[1]?.body)) as Record<string, unknown>;
    expect(body['device_type']).toBe('server');
    expect(body['adapter_key']).toBe('fake.simple');
    expect(body['management_endpoint']).toBe('10.0.0.5');
    expect(body['credentials']).toEqual({ username: 'admin', password: 'secret-123' });
    expect((body['connection_config'] as Record<string, unknown>)['verify_tls']).toBe(true);
  });
});
