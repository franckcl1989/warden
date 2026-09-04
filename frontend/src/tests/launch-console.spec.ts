import { createPinia, setActivePinia } from 'pinia';
import { mount } from '@vue/test-utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createMemoryHistory, createRouter, type RouteRecordRaw } from 'vue-router';

import LaunchConsoleDialog from '@/features/devices/LaunchConsoleDialog.vue';
import OperationsPanel from '@/features/devices/panels/OperationsPanel.vue';
import { useAuthStore } from '@/stores/auth';

const EMPTY_VIEW = { template: '<div />' };
const TEST_ROUTES: RouteRecordRaw[] = [
  { path: '/devices/:id', name: 'device-detail', component: EMPTY_VIEW },
  {
    path: '/terminal/sessions/:ticket',
    name: 'terminal-sessions',
    component: EMPTY_VIEW,
  },
  { path: '/:pathMatch(.*)*', name: 'fallback', component: EMPTY_VIEW },
];

/**
 * 远程连接启动流程测试（M3T4/M4T4/M5T4 / PLT-09，UI 流程）：
 * - console.kvm.open / console.dsm.open：点击"打开"先同步占位新标签页（避免
 *   弹窗拦截），再 POST /devices/{id}/launches，成功后导航到一次性消费 URL；
 * - console.ssh.open / console.telnet.open（M5T4 终端票据）：SPA 内跳转终端
 *   页 /terminal/sessions/{ticket}（WebSocket 由终端页建立），Telnet 在确认
 *   阶段持续提示明文弱协议风险；
 * - POST 失败时关闭占位标签页并渲染错误态；错误状态按错误码渲染中文提示。
 */
function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function errorBody(code: string, message: string, details: Record<string, unknown> = {}) {
  return { error: { code, message, details, request_id: 'r-1' } };
}

async function flushAll(): Promise<void> {
  for (let i = 0; i < 3; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

interface OpenedTab {
  location: { href: string };
  close: ReturnType<typeof vi.fn>;
}

function fakeTab(): OpenedTab {
  return { location: { href: '' }, close: vi.fn() };
}

/** 只在 window 上覆盖 open（不替换整个 window —— Element Plus 依赖 DOM API）。 */
function stubWindowOpen(impl: () => unknown): ReturnType<typeof vi.fn> {
  const open = vi.fn(impl);
  Object.defineProperty(window, 'open', {
    value: open,
    configurable: true,
    writable: true,
  });
  return open;
}

/** 无守卫的路由（本规格只关心 launch 流程的跳转目标）。 */
function makeRouter() {
  return createRouter({ history: createMemoryHistory(), routes: TEST_ROUTES });
}

async function mountDialog(
  fetchMock: (url: string, init?: RequestInit) => Promise<Response>,
  capability: { key: string; requirementId: string } = {
    key: 'console.kvm.open',
    requirementId: 'SRV-ACT-03',
  },
) {
  const pinia = createPinia();
  setActivePinia(pinia);
  const router = makeRouter();
  await router.push('/devices/d-1');
  vi.stubGlobal('fetch', fetchMock);
  const wrapper = mount(LaunchConsoleDialog, {
    props: {
      modelValue: true,
      deviceId: 'd-1',
      capabilityKey: capability.key,
      requirementId: capability.requirementId,
    },
    global: { plugins: [pinia, router] },
  });
  return { wrapper, router };
}

const CREATED = {
  launch_id: '0199-0000-0000-0001',
  expires_at: '2099-01-01T08:01:00Z',
  url: '/api/v1/launches/0199-0000-0000-0001',
};

describe('KVM 控制台启动流程（M3T4）', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    delete (window as { open?: unknown }).open;
  });

  it('点击打开控制台：POST 创建后把新标签页导航到一次性消费 URL', async () => {
    const tab = fakeTab();
    const openMock = stubWindowOpen(() => tab);
    const seen: Array<{ url: string; init?: RequestInit }> = [];
    const { wrapper } = await mountDialog(async (url, init) => {
      seen.push({ url: String(url), init });
      if (String(url).endsWith('/devices/d-1/launches')) {
        return jsonResponse(CREATED, 201);
      }
      return jsonResponse({}, 404);
    });

    await wrapper.get('[data-testid="launch-open"]').trigger('click');
    await flushAll();

    expect(seen).toHaveLength(1);
    const request = seen[0]!;
    expect(String(request.url)).toContain('/devices/d-1/launches');
    expect(JSON.parse(String(request.init?.body))).toEqual({ capability_key: 'console.kvm.open' });
    // 占位标签页在 POST 前同步打开，成功后导航到 /launches/{id}（vendor URL
    // 不进入 SPA 状态，由后端单次 GET 返回）。
    expect(openMock).toHaveBeenCalledWith('', '_blank');
    expect(tab.location.href).toBe(CREATED.url);
    expect(wrapper.text()).toContain('已在新标签页打开');
    expect(tab.close).not.toHaveBeenCalled();
  });

  it('not_configured 时显示配置缺失提示并关闭占位标签页', async () => {
    const tab = fakeTab();
    stubWindowOpen(() => tab);
    const { wrapper } = await mountDialog(async (url) => {
      if (String(url).endsWith('/devices/d-1/launches')) {
        return jsonResponse(
          errorBody('not_configured', '设备当前缺少必要配置，无法执行', {
            capability_key: 'console.kvm.open',
            missing: 'no_graphical_console（管理卡未提供可用的图形控制台）',
          }),
          422,
        );
      }
      return jsonResponse({}, 404);
    });

    await wrapper.get('[data-testid="launch-open"]').trigger('click');
    await flushAll();

    expect(tab.close).toHaveBeenCalled();
    expect(tab.location.href).toBe('');
    expect(wrapper.text()).toContain('设备当前未提供可用的 KVM 控制台');
    expect(wrapper.get('[data-testid="launch-error"]').text()).toContain('not_configured');
  });

  it('unsupported_operation 时显示能力不支持提示', async () => {
    stubWindowOpen(() => fakeTab());
    const { wrapper } = await mountDialog(async (url) => {
      if (String(url).endsWith('/devices/d-1/launches')) {
        return jsonResponse(
          errorBody('unsupported_operation', '该操作不是受支持的人工操作或不被目标设备支持', {
            requirement_id: 'SRV-ACT-03',
            capability_key: 'console.kvm.open',
          }),
          422,
        );
      }
      return jsonResponse({}, 404);
    });

    await wrapper.get('[data-testid="launch-open"]').trigger('click');
    await flushAll();

    expect(wrapper.text()).toContain('设备能力不支持或来源需求不匹配');
    expect(wrapper.find('[data-testid="launch-error"]').exists()).toBe(true);
  });

  it('rate_limited（会话/频率上限）时显示稍后重试提示', async () => {
    stubWindowOpen(() => fakeTab());
    const { wrapper } = await mountDialog(async (url) => {
      if (String(url).endsWith('/devices/d-1/launches')) {
        return jsonResponse(
          errorBody('rate_limited', '请求过于频繁，请稍后重试', {
            retry_after_seconds: 30,
            scope: 'launch_session_device',
          }),
          429,
        );
      }
      return jsonResponse({}, 404);
    });

    await wrapper.get('[data-testid="launch-open"]').trigger('click');
    await flushAll();

    expect(wrapper.text()).toContain('远程会话数量已达上限');
    expect(wrapper.find('[data-testid="launch-error"]').exists()).toBe(true);
  });

  it('validation_failed 时显示 ErrorDetail 并允许重试', async () => {
    stubWindowOpen(() => fakeTab());
    const { wrapper } = await mountDialog(async (url) => {
      if (String(url).endsWith('/devices/d-1/launches')) {
        return jsonResponse(errorBody('validation_failed', '设备已停用，无法创建远程连接'), 422);
      }
      return jsonResponse({}, 404);
    });

    await wrapper.get('[data-testid="launch-open"]').trigger('click');
    await flushAll();

    expect(wrapper.text()).toContain('设备已停用，无法创建远程连接');
    expect(wrapper.find('[data-testid="launch-retry"]').exists()).toBe(true);
  });

  it('浏览器拦截新标签页时如实提示票据已创建', async () => {
    stubWindowOpen(() => null);
    const { wrapper } = await mountDialog(async (url) => {
      if (String(url).endsWith('/devices/d-1/launches')) {
        return jsonResponse(CREATED, 201);
      }
      return jsonResponse({}, 404);
    });

    await wrapper.get('[data-testid="launch-open"]').trigger('click');
    await flushAll();

    expect(wrapper.text()).toContain('弹出窗口被浏览器拦截');
  });

  it('console.dsm.open：POST 携带 dsm 能力键并导航 DSM 管理界面（M4T4）', async () => {
    const tab = fakeTab();
    stubWindowOpen(() => tab);
    const seen: Array<{ url: string; init?: RequestInit }> = [];
    const { wrapper } = await mountDialog(
      async (url, init) => {
        seen.push({ url: String(url), init });
        if (String(url).endsWith('/devices/d-1/launches')) {
          return jsonResponse(CREATED, 201);
        }
        return jsonResponse({}, 404);
      },
      { key: 'console.dsm.open', requirementId: 'NAS-ACT-02' },
    );

    // 确认阶段的按钮文案提示 DSM 管理界面并注明"不注入密码"。
    expect(wrapper.text()).toContain('DSM 管理界面');
    expect(wrapper.text()).toContain('不注入密码');

    await wrapper.get('[data-testid="launch-open"]').trigger('click');
    await flushAll();

    expect(seen).toHaveLength(1);
    expect(String(seen[0]!.url)).toContain('/devices/d-1/launches');
    expect(JSON.parse(String(seen[0]!.init?.body))).toEqual({
      capability_key: 'console.dsm.open',
    });
    expect(tab.location.href).toBe(CREATED.url);
    expect(wrapper.text()).toContain('已在新标签页打开 DSM 管理界面');
    expect(tab.close).not.toHaveBeenCalled();
  });

  it('console.dsm.open 的 not_configured 显示指向 DSM 的配置提示', async () => {
    stubWindowOpen(() => fakeTab());
    const { wrapper } = await mountDialog(
      async (url) => {
        if (String(url).endsWith('/devices/d-1/launches')) {
          return jsonResponse(
            errorBody('not_configured', '设备当前缺少必要配置，无法执行', {
              capability_key: 'console.dsm.open',
              missing: 'no_dsm_origin：DSM System 端点未配置或不可达',
            }),
            422,
          );
        }
        return jsonResponse({}, 404);
      },
      { key: 'console.dsm.open', requirementId: 'NAS-ACT-02' },
    );

    await wrapper.get('[data-testid="launch-open"]').trigger('click');
    await flushAll();

    expect(wrapper.text()).toContain('设备当前未提供可用的 DSM 管理界面');
  });

  it('设备页签的 console.dsm.open 能力进入 launch 流程（console.* 路由）', async () => {
    const pinia = createPinia();
    setActivePinia(pinia);
    const auth = useAuthStore();
    auth.permissions = [
      'device.read',
      'operation.read',
      'operation.execute.low',
      'operation.execute.medium',
      'operation.execute.high',
    ];
    const router = makeRouter();
    await router.push('/devices/d-1');
    const tab = fakeTab();
    stubWindowOpen(() => tab);
    const seen: Array<{ url: string; init?: RequestInit }> = [];
    const fetchMock = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      seen.push({ url: String(url), init });
      if (String(url).endsWith('/devices/d-1/launches')) {
        return jsonResponse(CREATED, 201);
      }
      return jsonResponse({}, 404);
    });
    vi.stubGlobal('fetch', fetchMock);
    const wrapper = mount(OperationsPanel, {
      props: {
        deviceId: 'd-1',
        deviceName: 'nas-01',
        capabilities: [
          {
            capability_key: 'console.dsm.open',
            requirement_id: 'NAS-ACT-02',
            requirement_title: 'DSM Web 远程管理',
            support_state: 'supported',
            reason_code: null,
            detail: null,
            discovery_method: 'nas.synology_dsm',
            adapter_version: 'simulator-verified',
            last_checked_at: '2026-09-01T08:00:00Z',
          },
        ],
      },
      global: { plugins: [pinia, router] },
    });

    await wrapper.get('[data-testid="capability-console.dsm.open"]').trigger('click');
    await wrapper.get('[data-testid="launch-open"]').trigger('click');
    await flushAll();

    expect(wrapper.text()).toContain('需求编号：NAS-ACT-02');
    expect(seen).toHaveLength(1);
    expect(String(seen[0]!.url)).toContain('/devices/d-1/launches');
    expect(JSON.parse(String(seen[0]!.init?.body))).toEqual({
      capability_key: 'console.dsm.open',
    });
    expect(tab.location.href).toBe(CREATED.url);
  });
});

describe('SSH/Telnet 终端票据启动流程（M5T4）', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    delete (window as { open?: unknown }).open;
  });

  const TERMINAL_CREATED = {
    launch_id: '0199-0000-0000-0002',
    expires_at: '2099-01-01T08:01:00Z',
    url: '/api/v1/terminal/sessions/0199-0000-0000-0002',
  };

  it('console.ssh.open：POST 后 SPA 内跳转终端页（不打开新标签页）', async () => {
    const openMock = stubWindowOpen(() => fakeTab());
    const { wrapper, router } = await mountDialog(
      async (url) => {
        if (String(url).endsWith('/devices/d-1/launches')) {
          return jsonResponse(TERMINAL_CREATED, 201);
        }
        return jsonResponse({}, 404);
      },
      { key: 'console.ssh.open', requirementId: 'CORE-ACT-03' },
    );
    expect(wrapper.text()).toContain('SSH 终端');

    await wrapper.get('[data-testid="launch-open"]').trigger('click');
    await flushAll();

    expect(openMock).not.toHaveBeenCalled();
    expect(router.currentRoute.value.name).toBe('terminal-sessions');
    expect(router.currentRoute.value.params['ticket']).toBe(TERMINAL_CREATED.launch_id);
  });

  it('console.telnet.open：确认阶段持续显示弱协议提示并跳转终端页', async () => {
    stubWindowOpen(() => fakeTab());
    const { wrapper, router } = await mountDialog(
      async (url) => {
        if (String(url).endsWith('/devices/d-1/launches')) {
          return jsonResponse(TERMINAL_CREATED, 201);
        }
        return jsonResponse({}, 404);
      },
      { key: 'console.telnet.open', requirementId: 'CORE-ACT-03' },
    );
    expect(wrapper.text()).toContain('Telnet');
    expect(wrapper.text()).toContain('明文弱协议');

    await wrapper.get('[data-testid="launch-open"]').trigger('click');
    await flushAll();

    expect(router.currentRoute.value.name).toBe('terminal-sessions');
    expect(router.currentRoute.value.params['ticket']).toBe(TERMINAL_CREATED.launch_id);
  });

  it('console.ssh.open 的 not_configured 显示终端通道配置提示', async () => {
    stubWindowOpen(() => fakeTab());
    const { wrapper } = await mountDialog(
      async (url) => {
        if (String(url).endsWith('/devices/d-1/launches')) {
          return jsonResponse(
            errorBody('not_configured', '设备当前缺少必要配置，无法执行', {
              capability_key: 'console.ssh.open',
              missing: 'ssh_host_fingerprint_missing',
            }),
            422,
          );
        }
        return jsonResponse({}, 404);
      },
      { key: 'console.ssh.open', requirementId: 'CORE-ACT-03' },
    );

    await wrapper.get('[data-testid="launch-open"]').trigger('click');
    await flushAll();

    expect(wrapper.text()).toContain('SSH/Telnet 终端通道');
  });
});
