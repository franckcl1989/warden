import { createPinia, setActivePinia } from 'pinia';
import { mount } from '@vue/test-utils';
import { afterEach, describe, expect, it, vi } from 'vitest';

import BackupStatusPanel from '@/features/devices/panels/BackupStatusPanel.vue';
import { useAuthStore } from '@/stores/auth';

/**
 * NAS「任务与日志」页签备份/快照状态视图（NAS-ACT-05，M4T4）：
 * - 只渲染持久化的最近一次 backup.status.refresh 任务结果
 *   （GET /operations?capability_key=backup.status.refresh&device_id →
 *   GET /operations/{id} 的证据，结构照 M4T3 平台切片：evidence.execution.jobs/packages）；
 * - 无刷新任务 → "尚未刷新"空态 + 刷新入口（权限 + 能力支持时）；
 * - 最近刷新未成功 → 如实显示任务状态，不渲染任何清单；
 * - 观察员可查看结果但看不到刷新按钮；能力不支持时如实显示原因。
 */
function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function errorBody(code: string, message: string) {
  return { error: { code, message, details: {}, request_id: 'r-1' } };
}

async function flushAll(): Promise<void> {
  for (let i = 0; i < 4; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

const SUPPORTED_CAPABILITIES = [
  {
    capability_key: 'backup.status.refresh',
    requirement_id: 'NAS-ACT-05',
    requirement_title: '快照与备份任务状态查看',
    support_state: 'supported',
    reason_code: null,
    detail: null,
    discovery_method: 'nas.synology_dsm',
    adapter_version: 'simulator-verified',
    last_checked_at: '2026-09-01T08:00:00Z',
  },
];

const TASK_ID = '0199-0000-0000-00aa';

function listBody(items: unknown[], total: number) {
  return { items, page: 1, page_size: 1, total };
}

function listItem(state: string) {
  return {
    id: TASK_ID,
    requirement_id: 'NAS-ACT-05',
    capability_key: 'backup.status.refresh',
    risk_level: 'low',
    state,
    device: { id: 'd-1', name: 'nas-01' },
    requested_by: { id: 'u-1', username: 'admin' },
    progress_percent: 100,
    current_step: null,
    dispatch_started_at: '2026-09-01T08:00:01Z',
    device_job_id: null,
    timeout_at: null,
    result_summary: '刷新完成',
    error_code: null,
    error_detail: null,
    verification_state: 'passed',
    started_at: '2026-09-01T08:00:01Z',
    finished_at: '2026-09-01T08:00:02Z',
    created_at: '2026-09-01T08:00:00Z',
    updated_at: '2026-09-01T08:00:03Z',
    version: 3,
  };
}

/** 照 M4T3 平台切片：succeeded 任务的 evidence 结构。 */
function detailBody(state: string, withInventory = true) {
  const evidence: Record<string, unknown> = {
    state,
    dispatch_started_at: '2026-09-01T08:00:01Z',
    verification: {
      strategy: 'inventory_persisted',
      jobs_persisted: 2,
      packages_persisted: 2,
      readback_consistent: true,
    },
  };
  if (withInventory) {
    evidence['execution'] = {
      packages: [
        { name: 'Hyper Backup', package: 'hyper_backup', available: true },
        {
          name: 'Snapshot Replication',
          package: 'snapshot_replication',
          available: false,
          reason: 'not_installed',
        },
      ],
      jobs: [
        {
          name: 'Daily Backup',
          type: 'hyper_backup',
          status: 'success',
          last_run_at: '2026-09-01T00:30:00Z',
        },
        {
          name: 'Weekly Backup',
          type: 'hyper_backup',
          status: 'success',
          last_run_at: '2026-09-01T00:30:00Z',
        },
      ],
      observed_at: '2026-09-01T08:05:00Z',
    };
  }
  return {
    id: TASK_ID,
    requirement_id: 'NAS-ACT-05',
    capability_key: 'backup.status.refresh',
    risk_level: 'low',
    state,
    device: { id: 'd-1', name: 'nas-01' },
    requested_by: { id: 'u-1', username: 'admin' },
    progress_percent: 100,
    current_step: null,
    dispatch_started_at: '2026-09-01T08:00:01Z',
    device_job_id: null,
    timeout_at: null,
    result_summary: state === 'succeeded' ? '刷新完成' : null,
    error_code: state === 'succeeded' ? null : 'operation_failed',
    error_detail: state === 'succeeded' ? null : '模拟备份接口故障',
    verification_state: state === 'succeeded' ? 'passed' : 'failed',
    started_at: '2026-09-01T08:00:01Z',
    finished_at: state === 'succeeded' ? '2026-09-01T08:00:02Z' : '2026-09-01T08:00:05Z',
    created_at: '2026-09-01T08:00:00Z',
    updated_at: '2026-09-01T08:00:06Z',
    version: 4,
    conflict_scope: 'device',
    parameters: {},
    idempotency_key: 'ik-1',
    plan_hash: 'h-1',
    parameter_hash: 'h-2',
    adapter_version: 'simulator-verified',
    evidence,
    events: [],
  };
}

function isListUrl(url: string): boolean {
  return url.includes('/operations?') && !url.includes('/operations/0199');
}

async function mountPanel(
  fetchMock: (url: string, init?: RequestInit) => Promise<Response>,
  permissions: string[],
  capabilities: unknown[] = SUPPORTED_CAPABILITIES,
) {
  const pinia = createPinia();
  setActivePinia(pinia);
  const auth = useAuthStore();
  auth.user = {
    id: 'u-1',
    username: 'admin',
    display_name: '管理员',
    role: permissions.includes('operation.execute.low') ? 'admin' : 'viewer',
    status: 'active',
    must_change_password: false,
    last_login_at: null,
    created_at: '2026-09-01T00:00:00Z',
    updated_at: '2026-09-01T00:00:00Z',
    version: 1,
  };
  auth.permissions = permissions;
  vi.stubGlobal('fetch', fetchMock);
  const wrapper = mount(BackupStatusPanel, {
    props: {
      deviceId: 'd-1',
      deviceName: 'nas-01',
      capabilities: capabilities as never,
    },
    global: { plugins: [pinia] },
  });
  return wrapper;
}

describe('任务与日志：备份/快照状态视图（NAS-ACT-05）', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('无刷新任务时显示"尚未刷新"空态与刷新入口', async () => {
    const wrapper = await mountPanel(async (url) => {
      if (isListUrl(String(url))) {
        return jsonResponse(listBody([], 0));
      }
      return jsonResponse({}, 404);
    }, [
      'device.read',
      'operation.read',
      'operation.execute.low',
      'operation.execute.medium',
      'operation.execute.high',
    ]);
    await flushAll();

    expect(wrapper.text()).toContain('尚未刷新备份/快照任务状态');
    expect(wrapper.find('[data-testid="backup-refresh-button"]').exists()).toBe(true);
    expect(wrapper.get('[data-testid="backup-refresh-button"]').attributes('disabled')).toBe(
      undefined,
    );
    wrapper.unmount();
  });

  it('渲染最近一次成功刷新的任务证据：备份任务与功能包清单（不可用如实标注）', async () => {
    const wrapper = await mountPanel(async (url) => {
      if (isListUrl(String(url))) {
        return jsonResponse(listBody([listItem('succeeded')], 1));
      }
      if (String(url).endsWith(`/operations/${TASK_ID}`)) {
        return jsonResponse(detailBody('succeeded'));
      }
      return jsonResponse({}, 404);
    }, [
      'device.read',
      'operation.read',
      'operation.execute.low',
      'operation.execute.medium',
      'operation.execute.high',
    ]);
    await flushAll();

    expect(wrapper.text()).toContain('Daily Backup');
    expect(wrapper.text()).toContain('Weekly Backup');
    expect(wrapper.text()).toContain('hyper_backup');
    expect(wrapper.text()).toContain('Hyper Backup');
    expect(wrapper.text()).toContain('Snapshot Replication');
    // 不可用功能包显式标注原因（设备报告 not_installed），不做任何前端猜测
    expect(wrapper.text()).toContain('不可用');
    expect(wrapper.text()).toContain('（not_installed）');
    expect(wrapper.text()).toContain('任务 0199-0000-0000-00aa');
    expect(wrapper.find('[data-testid="backup-refresh-button"]').exists()).toBe(true);
    wrapper.unmount();
  });

  it('最近一次刷新未成功时如实显示任务状态，不渲染任何清单', async () => {
    const wrapper = await mountPanel(async (url) => {
      if (isListUrl(String(url))) {
        return jsonResponse(listBody([listItem('failed')], 1));
      }
      if (String(url).endsWith(`/operations/${TASK_ID}`)) {
        return jsonResponse(detailBody('failed'));
      }
      return jsonResponse({}, 404);
    }, [
      'device.read',
      'operation.read',
      'operation.execute.low',
      'operation.execute.medium',
      'operation.execute.high',
    ]);
    await flushAll();

    expect(wrapper.text()).toContain('失败');
    expect(wrapper.text()).toContain('模拟备份接口故障');
    // 未成功的任务证据不当作清单渲染
    expect(wrapper.text()).not.toContain('Daily Backup');
    expect(wrapper.find('[data-testid="backup-jobs-table"]').exists()).toBe(false);
    wrapper.unmount();
  });

  it('观察员可查看最近结果但没有刷新入口', async () => {
    const wrapper = await mountPanel(async (url) => {
      if (isListUrl(String(url))) {
        return jsonResponse(listBody([listItem('succeeded')], 1));
      }
      if (String(url).endsWith(`/operations/${TASK_ID}`)) {
        return jsonResponse(detailBody('succeeded'));
      }
      return jsonResponse({}, 404);
    }, ['device.read', 'monitor.read', 'operation.read']);
    await flushAll();

    expect(wrapper.text()).toContain('Daily Backup');
    expect(wrapper.find('[data-testid="backup-refresh-button"]').exists()).toBe(false);
    wrapper.unmount();
  });

  it('无执行权限时也不显示刷新按钮', async () => {
    const wrapper = await mountPanel(async (url) => {
      if (isListUrl(String(url))) {
        return jsonResponse(listBody([], 0));
      }
      return jsonResponse({}, 404);
    }, ['device.read', 'monitor.read', 'operation.read']);
    await flushAll();

    expect(wrapper.text()).toContain('尚未刷新备份/快照任务状态');
    expect(wrapper.find('[data-testid="backup-refresh-button"]').exists()).toBe(false);
    wrapper.unmount();
  });

  it('能力不支持（unsupported）时刷新按钮禁用并显示设备原因', async () => {
    const wrapper = await mountPanel(async (url) => {
      if (isListUrl(String(url))) {
        return jsonResponse(listBody([], 0));
      }
      return jsonResponse({}, 404);
    }, [
      'device.read',
      'operation.read',
      'operation.execute.low',
      'operation.execute.medium',
      'operation.execute.high',
    ], [
      {
        capability_key: 'backup.status.refresh',
        requirement_id: 'NAS-ACT-05',
        requirement_title: '快照与备份任务状态查看',
        support_state: 'unsupported',
        reason_code: 'no_certified_backup_api',
        detail: '真机证据待认证（ADR-018）',
        discovery_method: 'nas.synology_dsm',
        adapter_version: 'simulator-verified',
        last_checked_at: '2026-09-01T08:00:00Z',
      },
    ]);
    await flushAll();

    const button = wrapper.get('[data-testid="backup-refresh-button"]');
    expect(button.attributes('disabled')).toBeDefined();
    expect(wrapper.get('[data-testid="backup-refresh-denied"]').text()).toContain(
      '设备不支持',
    );
    expect(wrapper.get('[data-testid="backup-refresh-denied"]').text()).toContain(
      'no_certified_backup_api',
    );
    wrapper.unmount();
  });

  it('任务证据缺失清单结构时提示查看任务详情，不展示推测数据', async () => {
    const wrapper = await mountPanel(async (url) => {
      if (isListUrl(String(url))) {
        return jsonResponse(listBody([listItem('succeeded')], 1));
      }
      if (String(url).endsWith(`/operations/${TASK_ID}`)) {
        return jsonResponse(detailBody('succeeded', false));
      }
      return jsonResponse({}, 404);
    }, [
      'device.read',
      'operation.read',
      'operation.execute.low',
      'operation.execute.medium',
      'operation.execute.high',
    ]);
    await flushAll();

    expect(wrapper.find('[data-testid="backup-jobs-table"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="backup-packages-table"]').exists()).toBe(false);
    // 证据没有 execution 清单时不得显示"设备报告暂无备份任务"
    expect(wrapper.text()).not.toContain('设备报告暂无备份任务');
    expect(wrapper.get('[data-testid="backup-evidence-missing"]').text()).toContain(
      '未包含备份清单',
    );
    wrapper.unmount();
  });

  it('operations API 返回 permission_denied 时如实显示无权限', async () => {
    const wrapper = await mountPanel(
      async () => jsonResponse(errorBody('permission_denied', '无权限查看操作任务'), 403),
      [
        'device.read',
        'operation.read',
        'operation.execute.low',
        'operation.execute.medium',
        'operation.execute.high',
      ],
    );
    await flushAll();

    expect(wrapper.text()).toContain('无权限查看');
    wrapper.unmount();
  });
});
