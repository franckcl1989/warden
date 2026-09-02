import { createPinia, setActivePinia } from 'pinia';
import { mount } from '@vue/test-utils';
import { afterEach, describe, expect, it, vi } from 'vitest';

import OperationLaunchDialog from '@/features/operations/OperationLaunchDialog.vue';
import { useAuthStore } from '@/stores/auth';

/**
 * 操作发起流程测试（PLT-05，UI_SPEC §8）：
 * - 预览对话框字段来自预览 API 真实响应（影响/步骤/参数/风险/令牌期限）；
 * - 设备名精确匹配前提交按钮禁用；
 * - 每次提交生成新的 Idempotency-Key；
 * - 高风险操作服务端判定未复验（401 reauthentication_required）时先完成
 *   密码复验再继续（预览阶段与提交阶段两条路径）；
 * - 202 后携带任务 ID 通知父级跳转。
 */
function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

const PREVIEW = {
  requirement_id: 'SRV-ACT-02',
  capability_key: 'power.on',
  risk_level: 'high',
  target: { id: 'd-1', name: 'server-01' },
  normalized_parameters: {},
  impact: '服务器将从关机状态上电启动',
  steps: ['检查电源状态', '执行开机', '回读电源状态'],
  confirmation: { kind: 'type_device_name', expected: 'server-01' },
  preview_token: 'token-1',
  expires_at: '2099-01-01T08:30:00Z',
};

const PREVIEW_WITH_PARAMS = {
  ...PREVIEW,
  capability_key: 'interface.admin.set',
  normalized_parameters: { interface_id: 'GE0/0/12', enabled: false },
};

async function flushAll(): Promise<void> {
  for (let i = 0; i < 3; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

async function mountDialog(fetchMock: (url: string, init?: RequestInit) => Promise<Response>) {
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
  auth.permissions = [
    'operation.read',
    'operation.execute.low',
    'operation.execute.medium',
    'operation.execute.high',
  ];
  vi.stubGlobal('fetch', fetchMock);
  const wrapper = mount(OperationLaunchDialog, {
    props: {
      modelValue: true,
      device: { id: 'd-1', name: 'server-01' },
      capabilityKey: 'power.on',
      requirementId: 'SRV-ACT-02',
    },
    global: { plugins: [pinia] },
  });
  return { wrapper, auth };
}

describe('操作发起流程（PLT-05）', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('预览对话框展示 API 返回的风险/影响/步骤/参数/令牌期限', async () => {
    const { wrapper } = await mountDialog(async (url) => {
      if (String(url).includes('/operation-previews')) {
        return jsonResponse(PREVIEW_WITH_PARAMS);
      }
      return jsonResponse({});
    });
    await wrapper.get('[data-testid="preview-generate"]').trigger('click');
    await flushAll();
    expect(wrapper.text()).toContain('SRV-ACT-02');
    expect(wrapper.text()).toContain('高风险');
    expect(wrapper.text()).toContain('服务器将从关机状态上电启动');
    expect(wrapper.text()).toContain('interface_id = GE0/0/12');
    const steps = wrapper.findAll('[data-testid="preview-steps"] li');
    expect(steps.map((step) => step.text())).toEqual(['检查电源状态', '执行开机', '回读电源状态']);
    expect(wrapper.text()).toContain('2099-01-01');
  });

  it('设备名输入不匹配目标设备时提交按钮禁用，完全匹配后启用', async () => {
    const { wrapper } = await mountDialog(async (url) => {
      if (String(url).includes('/operation-previews')) {
        return jsonResponse(PREVIEW);
      }
      return jsonResponse({});
    });
    await wrapper.get('[data-testid="preview-generate"]').trigger('click');
    await flushAll();
    const submit = wrapper.get('[data-testid="confirm-submit"]');
    expect(submit.attributes('disabled')).toBeDefined();
    const input = wrapper.get('[data-testid="confirm-name-input"]');
    await input.setValue('server-99');
    await flushAll();
    expect(wrapper.get('[data-testid="confirm-submit"]').attributes('disabled')).toBeDefined();
    await input.setValue('server-01');
    await flushAll();
    expect(wrapper.get('[data-testid="confirm-submit"]').attributes('disabled')).toBeUndefined();
  });

  it('提交携带 Idempotency-Key 与确认文本，202 后发出 created 事件', async () => {
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (String(url).includes('/operation-previews')) {
        return jsonResponse(PREVIEW);
      }
      if (String(url).includes('/operations') && init?.method === 'POST') {
        return jsonResponse(
          {
            id: 'task-1',
            requirement_id: 'SRV-ACT-02',
            capability_key: 'power.on',
            risk_level: 'high',
            state: 'queued',
            device: { id: 'd-1', name: 'server-01' },
            requested_by: { id: 'u-1', username: 'admin' },
            progress_percent: 0,
            current_step: null,
            dispatch_started_at: null,
            device_job_id: null,
            timeout_at: null,
            result_summary: null,
            error_code: null,
            error_detail: null,
            verification_state: null,
            started_at: null,
            finished_at: null,
            created_at: '2099-01-01T08:10:00Z',
            updated_at: '2099-01-01T08:10:00Z',
            version: 1,
          },
          202,
        );
      }
      return jsonResponse({});
    });
    const { wrapper } = await mountDialog(fetchMock);
    await wrapper.get('[data-testid="preview-generate"]').trigger('click');
    await flushAll();
    await wrapper.get('[data-testid="confirm-name-input"]').setValue('server-01');
    await wrapper.get('[data-testid="confirm-submit"]').trigger('click');
    await flushAll();
    const submitCall = fetchMock.mock.calls.find(
      (call) => String(call[0]).includes('/operations') && call[1]?.method === 'POST',
    ) as unknown as [string, RequestInit];
    expect(submitCall).toBeDefined();
    const headers = submitCall[1].headers as Record<string, string>;
    expect(headers['Idempotency-Key']).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    );
    const body = JSON.parse(String(submitCall[1].body)) as Record<string, unknown>;
    expect(body).toEqual({ preview_token: 'token-1', confirmation_text: 'server-01' });
    const emitted = wrapper.emitted('created');
    expect(emitted).toBeDefined();
    expect((emitted?.[0] ?? [])[0]).toBe('task-1');
    expect(wrapper.emitted('update:modelValue')?.at(-1)).toEqual([false]);
  });

  it('预览被 401 reauthentication_required 拒绝时先复验密码再自动继续', async () => {
    let previewAttempts = 0;
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      void init;
      if (String(url).includes('/auth/reauth')) {
        return jsonResponse({ reauthenticated_until: '2099-01-01T08:35:00Z' });
      }
      if (String(url).includes('/operation-previews')) {
        previewAttempts += 1;
        if (previewAttempts === 1) {
          return jsonResponse(
            {
              error: {
                code: 'reauthentication_required',
                message: '高风险操作需要重新验证密码',
                details: {},
                request_id: 'r-1',
              },
            },
            401,
          );
        }
        return jsonResponse(PREVIEW);
      }
      return jsonResponse({});
    });
    const { wrapper, auth } = await mountDialog(fetchMock);
    void auth;
    await wrapper.get('[data-testid="preview-generate"]').trigger('click');
    await flushAll();
    expect(wrapper.text()).toContain('高风险操作需要重新验证当前用户密码');
    await wrapper.get('[data-testid="reauth-password-input"]').setValue('secret');
    await wrapper.get('[data-testid="reauth-submit"]').trigger('click');
    await flushAll();
    expect(previewAttempts).toBe(2);
    expect(wrapper.text()).toContain('服务器将从关机状态上电启动');
  });

  it('每次提交尝试使用新的 Idempotency-Key（复验后重试也重新生成）', async () => {
    let submitCount = 0;
    const keys: string[] = [];
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (String(url).includes('/auth/reauth')) {
        return jsonResponse({ reauthenticated_until: '2099-01-01T08:35:00Z' });
      }
      if (String(url).includes('/operation-previews')) {
        return jsonResponse(PREVIEW);
      }
      if (String(url).includes('/operations') && init?.method === 'POST') {
        submitCount += 1;
        const headers = init.headers as Record<string, string>;
        keys.push(headers['Idempotency-Key'] ?? '');
        if (submitCount === 1) {
          return jsonResponse(
            {
              error: {
                code: 'reauthentication_required',
                message: '高风险操作需要重新验证密码',
                details: {},
                request_id: 'r-2',
              },
            },
            401,
          );
        }
        return jsonResponse(
          {
            id: 'task-2',
            requirement_id: 'SRV-ACT-02',
            capability_key: 'power.on',
            risk_level: 'high',
            state: 'queued',
            device: { id: 'd-1', name: 'server-01' },
            requested_by: { id: 'u-1', username: 'admin' },
            progress_percent: 0,
            current_step: null,
            dispatch_started_at: null,
            device_job_id: null,
            timeout_at: null,
            result_summary: null,
            error_code: null,
            error_detail: null,
            verification_state: null,
            started_at: null,
            finished_at: null,
            created_at: '2099-01-01T08:10:00Z',
            updated_at: '2099-01-01T08:10:00Z',
            version: 1,
          },
          202,
        );
      }
      return jsonResponse({});
    });
    const { wrapper } = await mountDialog(fetchMock);
    await wrapper.get('[data-testid="preview-generate"]').trigger('click');
    await flushAll();
    await wrapper.get('[data-testid="confirm-name-input"]').setValue('server-01');
    await wrapper.get('[data-testid="confirm-submit"]').trigger('click');
    await flushAll();
    expect(wrapper.text()).toContain('高风险操作需要重新验证当前用户密码');
    await wrapper.get('[data-testid="reauth-password-input"]').setValue('secret');
    await wrapper.get('[data-testid="reauth-submit"]').trigger('click');
    await flushAll();
    expect(submitCount).toBe(2);
    expect(keys).toHaveLength(2);
    expect(keys[0]).not.toBe(keys[1]);
    expect(keys[1]).toBeTruthy();
    expect(wrapper.emitted('created')?.[0]?.[0]).toBe('task-2');
  });

  it('preview_stale 提交失败后回到可重新生成状态，不陷入失效确认循环', async () => {
    let previewCount = 0;
    let submitCount = 0;
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (String(url).includes('/operation-previews')) {
        previewCount += 1;
        return jsonResponse(PREVIEW);
      }
      if (String(url).includes('/operations') && init?.method === 'POST') {
        submitCount += 1;
        if (submitCount === 1) {
          return jsonResponse(
            {
              error: {
                code: 'preview_stale',
                message: '预览已失效',
                details: {},
                request_id: 'r-9',
              },
            },
            409,
          );
        }
        return jsonResponse(
          {
            id: 'task-9',
            requirement_id: 'SRV-ACT-02',
            capability_key: 'power.on',
            risk_level: 'high',
            state: 'queued',
            device: { id: 'd-1', name: 'server-01' },
            requested_by: { id: 'u-1', username: 'admin' },
            progress_percent: 0,
            current_step: null,
            dispatch_started_at: null,
            device_job_id: null,
            timeout_at: null,
            result_summary: null,
            error_code: null,
            error_detail: null,
            verification_state: null,
            started_at: null,
            finished_at: null,
            created_at: '2099-01-01T08:10:00Z',
            updated_at: '2099-01-01T08:10:00Z',
            version: 1,
          },
          202,
        );
      }
      return jsonResponse({});
    });
    const { wrapper } = await mountDialog(fetchMock);
    await wrapper.get('[data-testid="preview-generate"]').trigger('click');
    await flushAll();
    await wrapper.get('[data-testid="confirm-name-input"]').setValue('server-01');
    await wrapper.get('[data-testid="confirm-submit"]').trigger('click');
    await flushAll();
    expect(submitCount).toBe(1);
    expect(wrapper.find('[data-testid="flow-error"]').exists()).toBe(true);
    expect(wrapper.text()).toContain('预览已过期，请重新生成预览。');
    // 旧预览已作废：此刻只允许重新生成或修改参数，不再出现"重新确认"
    expect(wrapper.find('[data-testid="confirm-retry"]').exists()).toBe(false);
    await wrapper.get('[data-testid="regenerate-preview"]').trigger('click');
    await flushAll();
    expect(previewCount).toBe(2);
    expect(wrapper.text()).toContain('服务器将从关机状态上电启动');
    // 重新生成后是新预览：重新输入设备名后可以成功提交，循环被打破
    await wrapper.get('[data-testid="confirm-name-input"]').setValue('server-01');
    await wrapper.get('[data-testid="confirm-submit"]').trigger('click');
    await flushAll();
    expect(submitCount).toBe(2);
    expect(wrapper.emitted('created')?.[0]?.[0]).toBe('task-9');
  });

  it('预览令牌在确认页过期时提交禁用，可直接重新生成预览', async () => {
    let previewCount = 0;
    const fetchMock = vi.fn(async (url: string) => {
      if (String(url).includes('/operation-previews')) {
        previewCount += 1;
        if (previewCount === 1) {
          return jsonResponse({ ...PREVIEW, expires_at: '2020-01-01T00:00:00Z' });
        }
        return jsonResponse(PREVIEW);
      }
      return jsonResponse({});
    });
    const { wrapper } = await mountDialog(fetchMock);
    await wrapper.get('[data-testid="preview-generate"]').trigger('click');
    await flushAll();
    expect(wrapper.text()).toContain('（已过期，需重新生成）');
    expect(wrapper.get('[data-testid="confirm-submit"]').attributes('disabled')).toBeDefined();
    await wrapper.get('[data-testid="regenerate-preview"]').trigger('click');
    await flushAll();
    expect(previewCount).toBe(2);
    // 新预览有效：填入设备名后提交按钮恢复可用
    await wrapper.get('[data-testid="confirm-name-input"]').setValue('server-01');
    await flushAll();
    expect(wrapper.get('[data-testid="confirm-submit"]').attributes('disabled')).toBeUndefined();
  });
});
