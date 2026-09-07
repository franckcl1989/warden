import { createPinia, setActivePinia } from 'pinia';
import { mount } from '@vue/test-utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createMemoryHistory } from 'vue-router';

import AppShell from '@/components/AppShell.vue';
import { createAppRouter } from '@/router';
import { useAuthStore } from '@/stores/auth';
import { invalidateCache } from '@/lib/query-cache';
import type { SystemStatusResponse } from '@/api/types';

// 顶栏系统状态指示（UI_SPEC §2）：维护模式 → 红色 chip；组件降级/停止 →
// 琥珀色 chip；管理员可见；SSE system.status_changed 经 query-cache kind
// 'system' 触发重取（M6T3b，PLT-08）。
function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function userRow(role: 'admin' | 'operator') {
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

function statusFixture(overrides: Partial<SystemStatusResponse> = {}): SystemStatusResponse {
  return {
    as_of: '2026-09-07T08:00:00Z',
    maintenance: { active: false, since: null, reason: null },
    components: {
      api: { status: 'ok', detail: '' },
      database: { status: 'ok', detail: '' },
      file_storage: { status: 'ok', detail: '' },
      worker: { status: 'ok', detail: '', last_activity_at: null, collection_lag_seconds: null },
      ingest: {
        status: 'ok',
        detail: '',
        events_received_total: 0,
        last_received_at: null,
      },
    },
    queues: {
      operation_tasks: {
        queued: 0,
        running: 0,
        waiting_device: 0,
        verification_required: 0,
      },
      oldest_queued_age_seconds: null,
    },
    collection: { last_24h: { succeeded: 0, partial: 0, failed: 0 }, current_failures: [] },
    verification_required: { count: 0, oldest_at: null },
    ...overrides,
  };
}

async function flushAll(): Promise<void> {
  for (let i = 0; i < 3; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

async function mountShell(role: 'admin' | 'operator') {
  const pinia = createPinia();
  setActivePinia(pinia);
  const auth = useAuthStore();
  auth.user = userRow(role);
  auth.permissions = role === 'admin' ? ['system.read'] : ['device.read'];
  const router = createAppRouter(createMemoryHistory());
  await router.push('/overview');
  await router.isReady();
  const wrapper = mount(AppShell, {
    global: { plugins: [pinia, router] },
    slots: { default: '<div>page</div>' },
  });
  return { wrapper, router, auth };
}

describe('顶栏系统状态 chip（UI_SPEC §2 / PLT-08，仅管理员）', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('维护模式开启时显示红色 chip 并带原因', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse(
          statusFixture({
            maintenance: { active: true, since: '2026-09-07T06:00:00Z', reason: '发布窗口' },
          }),
        ),
      ),
    );
    const { wrapper } = await mountShell('admin');
    await flushAll();
    const chip = wrapper.find('[data-testid="system-status-chip"]');
    expect(chip.exists()).toBe(true);
    expect(chip.text()).toContain('维护模式');
    expect(chip.attributes('class')).toContain('system-chip--maintenance');
  });

  it('组件降级时显示琥珀色 chip', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse(
          statusFixture({
            components: {
              api: { status: 'ok', detail: '' },
              database: { status: 'degraded', detail: '' },
              file_storage: { status: 'ok', detail: '' },
              worker: { status: 'ok', detail: '', last_activity_at: null, collection_lag_seconds: null },
              ingest: { status: 'ok', detail: '', events_received_total: 0, last_received_at: null },
            },
          }),
        ),
      ),
    );
    const { wrapper } = await mountShell('admin');
    await flushAll();
    const chip = wrapper.find('[data-testid="system-status-chip"]');
    expect(chip.exists()).toBe(true);
    expect(chip.text()).toContain('系统异常');
    expect(chip.attributes('class')).toContain('system-chip--degraded');
  });

  it('全部正常时不显示 chip', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse(statusFixture())));
    const { wrapper } = await mountShell('admin');
    await flushAll();
    expect(wrapper.find('[data-testid="system-status-chip"]').exists()).toBe(false);
  });

  it('非管理员不显示 chip（也不请求 system.read 接口）', async () => {
    const urls: string[] = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      urls.push(String(input));
      return jsonResponse(statusFixture());
    });
    vi.stubGlobal('fetch', fetchMock);
    const { wrapper } = await mountShell('operator');
    await flushAll();
    expect(wrapper.find('[data-testid="system-status-chip"]').exists()).toBe(false);
    expect(urls.some((url) => url.includes('/system/status'))).toBe(false);
  });

  it('SSE system.status_changed（cache 失效）后 chip 刷新', async () => {
    let maintenanceOn = false;
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        const body = maintenanceOn
          ? statusFixture({ maintenance: { active: true, since: '2026-09-07T06:00:00Z', reason: null } })
          : statusFixture();
        return jsonResponse(body);
      }),
    );
    const { wrapper } = await mountShell('admin');
    await flushAll();
    expect(wrapper.find('[data-testid="system-status-chip"]').exists()).toBe(false);
    // realtime store 收到 system.status_changed 后执行 invalidateCache('system')，
    // 与顶栏 chip 注册的条目（kind system, id top-bar）相连。
    maintenanceOn = true;
    invalidateCache('system');
    await flushAll();
    const chip = wrapper.find('[data-testid="system-status-chip"]');
    expect(chip.exists()).toBe(true);
    expect(chip.text()).toContain('维护模式');
  });
});
