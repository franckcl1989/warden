import { createPinia, setActivePinia } from 'pinia';
import { mount } from '@vue/test-utils';
import { afterEach, describe, expect, it, vi } from 'vitest';

import LaunchConsoleDialog from '@/features/devices/LaunchConsoleDialog.vue';

/**
 * KVM 控制台启动流程测试（M3T4 / PLT-09 launch 部分，UI 流程）：
 * - 点击"打开控制台"先同步占位新标签页（避免弹窗拦截），再 POST
 *   /devices/{id}/launches，成功后把新标签页导航到返回的一次性消费 URL；
 * - POST 失败时关闭占位标签页并渲染错误态；
 * - 错误状态按错误码渲染：not_configured / unsupported_operation /
 *   rate_limited 各有中文提示，其他错误走 ErrorDetail；
 * - 弹窗被浏览器拦截时如实提示。
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

async function mountDialog(fetchMock: (url: string, init?: RequestInit) => Promise<Response>) {
  const pinia = createPinia();
  setActivePinia(pinia);
  vi.stubGlobal('fetch', fetchMock);
  const wrapper = mount(LaunchConsoleDialog, {
    props: {
      modelValue: true,
      deviceId: 'd-1',
      capabilityKey: 'console.kvm.open',
      requirementId: 'SRV-ACT-03',
    },
    global: { plugins: [pinia] },
  });
  return wrapper;
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
    const wrapper = await mountDialog(async (url, init) => {
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
    const wrapper = await mountDialog(async (url) => {
      if (String(url).endsWith('/devices/d-1/launches')) {
        return jsonResponse(
          errorBody('not_configured', '该能力当前缺少必要配置，无法执行', {
            capability_key: 'console.kvm.open',
            missing: 'no_graphical_console：管理卡未提供启用的图形控制台（KVM）',
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
    const wrapper = await mountDialog(async (url) => {
      if (String(url).endsWith('/devices/d-1/launches')) {
        return jsonResponse(
          errorBody('unsupported_operation', '该能力不承载可执行的人工操作或不被目标设备支持', {
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

  it('rate_limited（并发/频率上限）时显示请稍后重试提示', async () => {
    stubWindowOpen(() => fakeTab());
    const wrapper = await mountDialog(async (url) => {
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

  it('其他错误码显示 ErrorDetail 并允许重试', async () => {
    stubWindowOpen(() => fakeTab());
    const wrapper = await mountDialog(async (url) => {
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

  it('浏览器拦截新标签页时如实提示，不假装已打开', async () => {
    stubWindowOpen(() => null);
    const wrapper = await mountDialog(async (url) => {
      if (String(url).endsWith('/devices/d-1/launches')) {
        return jsonResponse(CREATED, 201);
      }
      return jsonResponse({}, 404);
    });

    await wrapper.get('[data-testid="launch-open"]').trigger('click');
    await flushAll();

    expect(wrapper.text()).toContain('弹出窗口被浏览器拦截');
  });
});

