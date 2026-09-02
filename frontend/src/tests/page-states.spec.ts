import { createPinia, setActivePinia } from 'pinia';
import { mount } from '@vue/test-utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createMemoryHistory } from 'vue-router';

import AlertsView from '@/features/alerts/AlertsView.vue';
import AuditView from '@/features/audit/AuditView.vue';
import FilesView from '@/features/files/FilesView.vue';
import OverviewView from '@/features/overview/OverviewView.vue';
import { createAppRouter } from '@/router';
import { useAuthStore } from '@/stores/auth';

/**
 * 页面状态测试（UI_SPEC §5/§6/§9）：alerts 筛选、overview 需要关注按服务端
 * 顺序渲染、audit 403 状态、files 上传向导状态流转。
 */
function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function errorBody(code: string, message: string, status: number): Response {
  return jsonResponse({ error: { code, message, details: {}, request_id: 'r' } }, status);
}

async function flushAll(): Promise<void> {
  for (let i = 0; i < 4; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

function seedAuth(role: 'admin' | 'operator' | 'viewer' = 'admin') {
  const auth = useAuthStore();
  auth.user = {
    id: 'u-1',
    username: 'admin',
    display_name: '管理员',
    role,
    status: 'active',
    must_change_password: false,
    last_login_at: null,
    created_at: '2026-09-01T00:00:00Z',
    updated_at: '2026-09-01T00:00:00Z',
    version: 1,
  };
  auth.permissions =
    role === 'admin'
      ? [
          'monitor.read',
          'operation.read',
          'file.metadata.read',
          'file.manage.input',
          'file.download.output',
          'file.delete',
          'audit.read',
        ]
      : ['monitor.read', 'operation.read', 'file.metadata.read', 'audit.read'];
}

async function mountPage(
  component: unknown,
  path: string,
  fetchMock: (url: string, init?: RequestInit) => Promise<Response>,
) {
  const pinia = createPinia();
  setActivePinia(pinia);
  seedAuth();
  vi.stubGlobal('fetch', fetchMock);
  const router = createAppRouter(createMemoryHistory());
  await router.push(path);
  await router.isReady();
  const wrapper = mount(component as never, {
    global: { plugins: [pinia, router] },
  });
  await flushAll();
  return { wrapper, router };
}

describe('alerts 页（PLT-04）', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function alertRow(id: string, title: string) {
    return {
      id,
      device: { id: 'd-1', name: 'server-01', device_type: 'server' },
      component_id: null,
      rule_key: 'device.offline',
      severity: 'critical',
      status: 'active',
      title,
      first_occurred_at: '2026-09-01T07:00:00Z',
      last_occurred_at: '2026-09-01T08:00:00Z',
      resolved_at: null,
    };
  }

  function listResponse(items: unknown[], total: number) {
    return { items, page: 1, page_size: 20, total };
  }

  it('渲染未恢复问题行并展示严重级别/状态标签', async () => {
    const { wrapper } = await mountPage(AlertsView, '/alerts', async (url) => {
      if (String(url).includes('/alerts?')) {
        return jsonResponse(listResponse([alertRow('a-1', '设备离线')], 1));
      }
      return jsonResponse({});
    });
    expect(wrapper.find('[data-testid="alerts-table"]').exists()).toBe(true);
    expect(wrapper.text()).toContain('设备离线');
    expect(wrapper.text()).toContain('server-01');
    expect(wrapper.text()).toContain('严重');
    expect(wrapper.text()).toContain('未恢复');
    expect(wrapper.text()).toContain('device.offline');
  });

  it('切换到已恢复以 status=resolved 重新请求并显示已恢复列', async () => {
    const fetchMock = vi.fn(async (url: string) => {
      const u = String(url);
      if (u.includes('/alerts?')) {
        const status = new URLSearchParams(u.split('?')[1] ?? '').get('status');
        if (status === 'resolved') {
          return jsonResponse(
            listResponse(
              [
                {
                  ...alertRow('a-2', '设备离线'),
                  status: 'resolved',
                  resolved_at: '2099-01-01T08:30:00Z',
                },
              ],
              1,
            ),
          );
        }
        return jsonResponse(listResponse([], 0));
      }
      return jsonResponse({});
    });
    const { wrapper } = await mountPage(AlertsView, '/alerts', fetchMock);
    const toggle = wrapper.get('[data-testid="alert-status-toggle"]');
    const radioGroup = toggle.findComponent({ name: 'ElRadioGroup' });
    await radioGroup.vm.$emit('update:modelValue', 'resolved');
    await radioGroup.vm.$emit('change', 'resolved');
    await flushAll();
    const url = String(fetchMock.mock.calls.at(-1)?.[0] ?? '');
    expect(new URLSearchParams(url.split('?')[1] ?? '').get('status')).toBe('resolved');
    expect(wrapper.text()).toContain('已恢复');
    expect(toggle.findAll('.el-radio-button').length).toBeGreaterThanOrEqual(2);
  });

  it('API 返回 permission_denied 时显示无权限状态', async () => {
    const { wrapper } = await mountPage(AlertsView, '/alerts', async () =>
      errorBody('permission_denied', '权限不足', 403),
    );
    expect(wrapper.text()).toContain('无权限查看该页面');
  });
});

describe('overview 页（PLT-03）', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('需要关注按服务端返回顺序渲染（不重排）', async () => {
    const overview = {
      as_of: '2026-09-01T08:00:00Z',
      stats: {
        device_total: 2,
        reachability: { online: 1, offline: 1, unknown: 0 },
        health: { healthy: 1, warning: 0, critical: 1, unknown: 0 },
        active_critical_alerts: 1,
        operations_running: 1,
        operations_verification_required: 1,
      },
      device_types: {
        server: {
          reachability: { online: 1, offline: 1, unknown: 0 },
          health: { healthy: 1, warning: 0, critical: 1, unknown: 0 },
        },
      },
      attention: [
        {
          device: {
            id: 'd-2',
            name: 'z-server',
            device_type: 'server',
            vendor: 'Fake',
            model: 'M2',
          },
          problems: [
            {
              id: 'al-1',
              rule_key: 'device.offline',
              severity: 'critical',
              title: '设备离线',
              first_occurred_at: '2026-09-01T07:00:00Z',
              last_occurred_at: '2026-09-01T08:00:00Z',
            },
          ],
          last_collected_at: null,
          rank: 0,
        },
        {
          device: {
            id: 'd-1',
            name: 'a-server',
            device_type: 'server',
            vendor: 'Fake',
            model: 'M1',
          },
          problems: [
            {
              id: 'al-2',
              rule_key: 'health.state',
              severity: 'warning',
              title: '电源警告',
              first_occurred_at: '2026-09-01T06:00:00Z',
              last_occurred_at: '2026-09-01T08:00:00Z',
            },
          ],
          last_collected_at: '2026-09-01T07:59:00Z',
          rank: 3,
        },
      ],
      recent_operations: [],
    };
    const { wrapper } = await mountPage(OverviewView, '/overview', async (url) => {
      const u = String(url);
      if (u.endsWith('/overview')) {
        return jsonResponse(overview);
      }
      if (u.includes('/operations?')) {
        return jsonResponse({ items: [], page: 1, page_size: 5, total: 0 });
      }
      return jsonResponse({});
    });
    expect(wrapper.get('[data-testid="overview-stats"]').text()).toContain('2');
    expect(wrapper.get('[data-testid="overview-attention"]').text()).toContain('设备离线');
    expect(wrapper.get('[data-testid="overview-attention"]').text()).toContain('电源警告');
    const names = wrapper
      .findAll('[data-testid="attention-device"]')
      .map((button) => button.text());
    // 服务端顺序 z-server(离线 rank0) 在 a-server(警告) 之前；前端不得重排
    expect(names).toEqual(['z-server', 'a-server']);
    expect(wrapper.get('[data-testid="overview-as-of"]').text()).toContain('数据截至：');
  });

  it('空关注列表显示"当前没有需要关注的设备"', async () => {
    const overview = {
      as_of: '2026-09-01T08:00:00Z',
      stats: {
        device_total: 0,
        reachability: {},
        health: {},
        active_critical_alerts: 0,
        operations_running: 0,
        operations_verification_required: 0,
      },
      device_types: {},
      attention: [],
      recent_operations: [],
    };
    const { wrapper } = await mountPage(OverviewView, '/overview', async (url) => {
      const u = String(url);
      if (u.endsWith('/overview')) {
        return jsonResponse(overview);
      }
      if (u.includes('/operations?')) {
        return jsonResponse({ items: [], page: 1, page_size: 5, total: 0 });
      }
      return jsonResponse({});
    });
    expect(wrapper.text()).toContain('当前没有需要关注的设备');
    expect(wrapper.text()).toContain('暂无人工操作任务');
  });
});

describe('audit 页（PLT-07）', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('403 时显示无权限状态', async () => {
    const { wrapper } = await mountPage(AuditView, '/audit', async () =>
      errorBody('permission_denied', '权限不足', 403),
    );
    expect(wrapper.text()).toContain('无权限查看该页面');
  });
});

describe('files 页上传向导（PLT-06）', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  class FakeXHR {
    static lastInstance: FakeXHR | null = null;
    url = '';
    method = '';
    status = 0;
    responseText = '';
    sentBody: unknown = null;
    private listeners = new Map<string, (() => void)[]>();

    upload = {
      addEventListener: (type: string, listener: () => void) => {
        void type;
        void listener;
      },
    };

    open(method: string, url: string): void {
      this.method = method;
      this.url = url;
    }

    setRequestHeader(): void {
      // no-op
    }

    send(body: unknown): void {
      this.sentBody = body;
      FakeXHR.lastInstance = this;
      this.status = 200;
      this.responseText = JSON.stringify({ received_bytes: 10 });
      queueMicrotask(() => {
        for (const listener of this.listeners.get('load') ?? []) {
          listener();
        }
      });
    }

    addEventListener(type: string, listener: () => void): void {
      const list = this.listeners.get(type) ?? [];
      list.push(listener);
      this.listeners.set(type, list);
    }
  }

  function fileView(id: string, extra: Record<string, unknown> = {}) {
    return {
      id,
      file_type: 'firmware',
      original_filename: 'fw.bin',
      size_bytes: 10,
      mime_type: 'application/octet-stream',
      sha256: null,
      storage_backend: 'disk',
      encrypted: true,
      key_version: 1,
      status: 'uploading',
      metadata: {},
      uploaded_by: { id: 'u-1', username: 'admin' },
      links: [],
      created_at: '2026-09-01T08:00:00Z',
      updated_at: '2026-09-01T08:00:00Z',
      version: 1,
      ...extra,
    };
  }

  it('向导按 创建会话→上传→完成 流转并刷新列表', async () => {
    vi.stubGlobal('XMLHttpRequest', FakeXHR);
    const uploadIds: string[] = [];
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      const u = String(url);
      if (u.includes('/files/uploads/') && u.endsWith('/complete')) {
        return jsonResponse(fileView('u-1', { status: 'ready', sha256: 'a'.repeat(64) }));
      }
      if (u.includes('/files/uploads') && init?.method === 'POST') {
        uploadIds.push('u-1');
        return jsonResponse(fileView('u-1'), 201);
      }
      if (u.includes('/files?')) {
        return jsonResponse({
          items: [fileView('u-1', { status: 'ready', sha256: 'a'.repeat(64) })],
          page: 1,
          page_size: 20,
          total: 1,
        });
      }
      return jsonResponse({});
    });
    const { wrapper } = await mountPage(FilesView, '/files', fetchMock);
    await wrapper.get('[data-testid="open-upload"]').trigger('click');
    await flushAll();
    expect(wrapper.find('[data-testid="upload-wizard"]').exists()).toBe(true);
    const input = wrapper.get('[data-testid="upload-file-input"]').element as HTMLInputElement;
    Object.defineProperty(input, 'files', { value: [new File(['0123456789'], 'fw.bin')] });
    await input.dispatchEvent(new Event('change'));
    await wrapper.get('[data-testid="start-upload"]').trigger('click');
    await flushAll();
    expect(uploadIds).toEqual(['u-1']);
    const putUrl = FakeXHR.lastInstance?.url ?? '';
    expect(putUrl).toContain('/files/uploads/u-1/content');
    expect(wrapper.text()).toContain('文件上传完成：fw.bin');
    const listCalls = fetchMock.mock.calls.filter((call) => String(call[0]).includes('/files?'));
    expect(listCalls.length).toBeGreaterThanOrEqual(2);
  });
});
