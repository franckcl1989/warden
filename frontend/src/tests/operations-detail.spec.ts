import { createPinia, setActivePinia } from 'pinia';
import { mount } from '@vue/test-utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createMemoryHistory } from 'vue-router';

import OperationsDetailView from '@/features/operations/OperationsDetailView.vue';
import { createAppRouter } from '@/router';
import { useAuthStore } from '@/stores/auth';

/**
 * 任务详情操作入口权限（M6T1 权限统一，SECURITY §3.1 / UI_SPEC §12）：
 * - 重新回读/人工核验只对管理员显示（后端 require_admin 门禁）；
 * - 取消任务要求 operation.execute.<risk>（后端 cancel_task 按风险等级
 *   校验执行权限）：观察员即使任务在 queued/running 也看不到取消入口；
 * - 运维员持有对应风险等级权限时可见取消。
 */
function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

const TASK_ID = 'task-1';

function taskDetail(state: string, extra: Record<string, unknown> = {}) {
  return {
    id: TASK_ID,
    requirement_id: 'SRV-ACT-02',
    capability_key: 'power.on',
    risk_level: 'high',
    state,
    device: { id: 'd-1', name: 'server-01' },
    requested_by: { id: 'u-1', username: 'admin' },
    progress_percent: state === 'running' ? 40 : 100,
    current_step: null,
    dispatch_started_at: state === 'running' ? '2026-09-04T08:00:01Z' : null,
    device_job_id: null,
    timeout_at: '2026-09-04T08:10:00Z',
    result_summary: state === 'succeeded' ? '已完成' : null,
    error_code: null,
    error_detail: null,
    verification_state: state === 'verification_required' ? 'pending' : null,
    started_at: '2026-09-04T08:00:01Z',
    finished_at: null,
    created_at: '2026-09-04T08:00:00Z',
    updated_at: '2026-09-04T08:00:02Z',
    version: 1,
    conflict_scope: 'device',
    parameters: {},
    idempotency_key: 'ik-1',
    plan_hash: 'h-1',
    parameter_hash: 'h-2',
    adapter_version: 'simulator-verified',
    evidence: null,
    events: [],
    ...extra,
  };
}

function seedAuth(role: 'admin' | 'operator' | 'viewer', permissions: string[]): void {
  const auth = useAuthStore();
  auth.user = {
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
  auth.permissions = permissions;
}

async function flush(): Promise<void> {
  for (let i = 0; i < 4; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

async function mountDetail(state: string, role: 'admin' | 'operator' | 'viewer', permissions: string[]) {
  const pinia = createPinia();
  setActivePinia(pinia);
  seedAuth(role, permissions);
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      if (String(url).includes(`/operations/${TASK_ID}`)) {
        return jsonResponse(taskDetail(state));
      }
      return jsonResponse({}, 404);
    }),
  );
  const router = createAppRouter(createMemoryHistory());
  await router.push(`/operations/${TASK_ID}`);
  await router.isReady();
  const wrapper = mount(OperationsDetailView, {
    global: { plugins: [pinia, router] },
  });
  await flush();
  return wrapper;
}

describe('任务详情操作入口权限（M6T1）', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('管理员在 queued 高风险任务上可取消', async () => {
    const wrapper = await mountDetail('queued', 'admin', [
      'operation.read',
      'operation.execute.low',
      'operation.execute.medium',
      'operation.execute.high',
    ]);
    expect(wrapper.find('[data-testid="cancel-task"]').exists()).toBe(true);
    wrapper.unmount();
  });

  it('观察员看不到取消入口（无 operation.execute.*，即使任务 queued）', async () => {
    const wrapper = await mountDetail('queued', 'viewer', [
      'device.read',
      'monitor.read',
      'operation.read',
    ]);
    expect(wrapper.find('[data-testid="cancel-task"]').exists()).toBe(false);
    expect(wrapper.text()).not.toContain('取消任务');
    wrapper.unmount();
  });

  it('运维员持有对应风险权限时可见取消，但不显示管理员专属的重新回读/人工核验', async () => {
    const wrapper = await mountDetail('verification_required', 'operator', [
      'device.read',
      'monitor.read',
      'operation.read',
      'operation.execute.low',
      'operation.execute.medium',
      'operation.execute.high',
    ]);
    // verification_required 不是可取消状态；管理员专属核验操作不显示
    expect(wrapper.find('[data-testid="cancel-task"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="verify-actions"]').exists()).toBe(false);
    expect(wrapper.text()).not.toContain('重新回读');
    wrapper.unmount();
  });

  it('管理员在 verification_required 任务上看到重新回读与人工核验入口', async () => {
    const wrapper = await mountDetail('verification_required', 'admin', [
      'operation.read',
      'operation.execute.low',
      'operation.execute.medium',
      'operation.execute.high',
    ]);
    expect(wrapper.find('[data-testid="verify-actions"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="verify-readback"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="open-resolve"]').exists()).toBe(true);
    wrapper.unmount();
  });
});
