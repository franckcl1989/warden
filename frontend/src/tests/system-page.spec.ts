import { createPinia, setActivePinia } from 'pinia';
import { mount } from '@vue/test-utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createMemoryHistory } from 'vue-router';

import SystemView from '@/features/system/SystemView.vue';
import { createAppRouter } from '@/router';
import { useAuthStore } from '@/stores/auth';
import type { SystemStatusResponse } from '@/api/types';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function userRow(role: 'admin' | 'operator' | 'viewer') {
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

function seedUser(role: 'admin' | 'operator' | 'viewer') {
  const auth = useAuthStore();
  auth.user = userRow(role);
  auth.permissions = role === 'admin' ? ['system.read'] : ['device.read'];
}

function statusFixture(overrides: Partial<SystemStatusResponse> = {}): SystemStatusResponse {
  return {
    as_of: '2026-09-07T08:00:00Z',
    maintenance: { active: false, since: null, reason: null },
    components: {
      api: { status: 'ok', detail: '' },
      database: { status: 'ok', detail: '数据库连接正常' },
      file_storage: { status: 'ok', detail: '文件卷可写' },
      worker: {
        status: 'ok',
        detail: '',
        last_activity_at: '2026-09-07T07:59:30Z',
        collection_lag_seconds: null,
      },
      ingest: {
        status: 'ok',
        detail: '',
        events_received_total: 12,
        last_received_at: '2026-09-07T07:55:00Z',
      },
    },
    queues: {
      operation_tasks: {
        queued: 1,
        running: 2,
        waiting_device: 0,
        verification_required: 3,
      },
      oldest_queued_age_seconds: 45,
    },
    collection: {
      last_24h: { succeeded: 42, partial: 3, failed: 1 },
      current_failures: [
        {
          device_id: 'd-1',
          device_name: 'core-s5732',
          collection_type: 'logs',
          error_code: 'network_unreachable',
          failed_at: '2026-09-07T07:50:00Z',
        },
      ],
    },
    verification_required: { count: 3, oldest_at: '2026-09-07T07:30:00Z' },
    ...overrides,
  };
}

async function flushAll(): Promise<void> {
  for (let i = 0; i < 3; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

async function mountPage(role: 'admin' | 'operator' | 'viewer') {
  const pinia = createPinia();
  setActivePinia(pinia);
  seedUser(role);
  const router = createAppRouter(createMemoryHistory());
  await router.push('/system');
  await router.isReady();
  const wrapper = mount(SystemView, {
    global: { plugins: [pinia, router] },
  });
  return { wrapper, router };
}

describe('系统状态页（PLT-08，仅管理员）', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('非管理员渲染无权限状态', async () => {
    const { wrapper } = await mountPage('operator');
    await flushAll();
    expect(wrapper.text()).toContain('无权限查看该页面');
  });

  it('管理员渲染组件状态与摘要区块', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse(statusFixture())));
    const { wrapper } = await mountPage('admin');
    await flushAll();
    expect(wrapper.find('[data-testid="system-page"]').exists()).toBe(true);
    expect(wrapper.text()).toContain('组件状态');
    expect(wrapper.find('[data-testid="component-worker"]').text()).toContain('正常');
    expect(wrapper.find('[data-testid="component-ingest"]').text()).toContain('累计接收事件：12');
    expect(wrapper.find('[data-testid="queue-verification_required"]').text()).toContain('3');
    expect(wrapper.find('[data-testid="queue-queued"]').text()).toContain('1');
    expect(wrapper.find('[data-testid="current-failures"]').text()).toContain('core-s5732');
    expect(wrapper.text()).toContain('network_unreachable');
    expect(wrapper.find('[data-testid="verification-count"]').text()).toBe('3');
    expect(wrapper.find('[data-testid="verification-link"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="maintenance-banner"]').exists()).toBe(false);
  });

  it('维护模式 banner 展示 since 与 reason', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse(
          statusFixture({
            maintenance: {
              active: true,
              since: '2026-09-07T06:00:00Z',
              reason: '发布窗口',
            },
          }),
        ),
      ),
    );
    const { wrapper } = await mountPage('admin');
    await flushAll();
    const banner = wrapper.find('[data-testid="maintenance-banner"]');
    expect(banner.exists()).toBe(true);
    expect(banner.text()).toContain('维护模式中');
    expect(banner.text()).toContain('发布窗口');
  });

  it('降级组件状态与 detail 原文展示', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse(
          statusFixture({
            components: {
              api: { status: 'ok', detail: '' },
              database: { status: 'ok', detail: '数据库连接正常' },
              file_storage: { status: 'unavailable', detail: '文件卷不可用（只读或挂载异常）' },
              worker: {
                status: 'degraded',
                detail: '存在超过两个采集周期未被领取的采集任务',
                last_activity_at: '2026-09-07T07:59:30Z',
                collection_lag_seconds: 71,
              },
              ingest: { status: 'stopped', detail: '接收器心跳过期', events_received_total: 0, last_received_at: null },
            },
          }),
        ),
      ),
    );
    const { wrapper } = await mountPage('admin');
    await flushAll();
    expect(wrapper.find('[data-testid="component-file_storage"]').text()).toContain('不可用');
    expect(wrapper.find('[data-testid="component-worker"]').text()).toContain('降级');
    expect(wrapper.find('[data-testid="component-worker"]').text()).toContain('采集领取延迟：1 分钟');
    expect(wrapper.find('[data-testid="component-ingest"]').text()).toContain('已停止');
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
    const { wrapper } = await mountPage('admin');
    await flushAll();
    expect(wrapper.text()).toContain('无权限查看该页面');
  });
});
