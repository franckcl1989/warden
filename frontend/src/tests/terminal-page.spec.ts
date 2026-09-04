import { createPinia, setActivePinia } from 'pinia';
import { mount } from '@vue/test-utils';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createMemoryHistory, createRouter, type RouteRecordRaw } from 'vue-router';

import { apiBaseUrl } from '@/api/client';
import TerminalPage from '@/features/terminal/TerminalPage.vue';

/**
 * 浏览器终端页测试（M5T4 / PLT-09 终端部分）：
 * - 挂载即按 ticket 建立 WebSocket（ws(s)://host + /api/v1/terminal/sessions/..，
 *   二进制帧 = 终端字节流、文本帧 = 控制消息）；
 * - ready 控制帧进入 open 状态并记录 session_id/protocol；
 * - closed 帧把关闭原因转成中文展示；
 * - refused 帧（accept 后拒绝契约：机器 reason 键 + code 4000-4999 关闭码）
 *   按 reason 显示具体中文；帧丢失时按关闭码兜底；
 * - Telnet 会话显示持久弱协议横幅；
 * - "关闭会话"调用 POST /terminal/sessions/{id}/close；
 * - 终端内容（二进制帧）只写入 xterm，不进入任何 DOM 文本断言之外的状态。
 */

const EMPTY_VIEW = { template: '<div />' };
const ROUTES: RouteRecordRaw[] = [
  { path: '/terminal/sessions/:ticket', name: 'terminal-sessions', component: EMPTY_VIEW },
  { path: '/:pathMatch(.*)*', name: 'fallback', component: EMPTY_VIEW },
];

const mocked = vi.hoisted(() => {
  class FakeTerminal {
    static last: FakeTerminal | null = null;
    written: Array<string | Uint8Array> = [];
    cols = 80;
    rows = 24;
    disposed = false;
    fit = vi.fn();
    open = vi.fn();
    loadAddon = vi.fn();
    dispose = vi.fn(function (this: FakeTerminal) {
      this.disposed = true;
    });

    constructor() {
      FakeTerminal.last = this;
    }

    write(data: string | Uint8Array): void {
      this.written.push(data);
    }
  }

  class FakeFitAddon {
    fit = vi.fn();
  }

  return { FakeTerminal, FakeFitAddon };
});

vi.mock('@xterm/xterm', () => ({
  Terminal: mocked.FakeTerminal,
}));
vi.mock('@xterm/addon-fit', () => ({
  FitAddon: mocked.FakeFitAddon,
}));
vi.mock('@xterm/xterm/css/xterm.css', () => ({}));

interface FakeSocket {
  url: string;
  binaryType: string;
  readyState: number;
  sent: Array<string | ArrayBuffer>;
  onopen: ((event: unknown) => void) | null;
  onmessage: ((event: MessageEvent<string | ArrayBuffer | Blob>) => void) | null;
  onclose: ((event: CloseEvent) => void) | null;
  onerror: ((event: unknown) => void) | null;
  close: ReturnType<typeof vi.fn>;
}

const sockets: FakeSocket[] = [];

class FakeWebSocketImpl implements FakeSocket {
  static OPEN = 1;
  static CONNECTING = 0;
  static CLOSING = 2;
  static CLOSED = 3;

  url: string;
  binaryType = '';
  readyState = FakeWebSocketImpl.CONNECTING;
  sent: Array<string | ArrayBuffer> = [];
  onopen: ((event: unknown) => void) | null = null;
  onmessage: ((event: MessageEvent<string | ArrayBuffer | Blob>) => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;
  onerror: ((event: unknown) => void) | null = null;
  close = vi.fn(() => {
    this.readyState = FakeWebSocketImpl.CLOSED;
    this.onclose?.({ code: 1000, reason: '' } as CloseEvent);
  });

  constructor(url: string | URL) {
    this.url = String(url);
    sockets.push(this);
  }

  send(data: string | ArrayBuffer): void {
    this.sent.push(data);
  }
}

function emitText(socket: FakeSocket, payload: unknown): void {
  socket.onmessage?.({ data: JSON.stringify(payload) } as MessageEvent<string>);
}

function emitBytes(socket: FakeSocket, bytes: Uint8Array): void {
  socket.onmessage?.({ data: bytes.buffer as ArrayBuffer } as MessageEvent<ArrayBuffer>);
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

async function flushAll(): Promise<void> {
  for (let i = 0; i < 4; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

async function mountPage(ticket = 't-1') {
  const pinia = createPinia();
  setActivePinia(pinia);
  const router = createRouter({ history: createMemoryHistory(), routes: ROUTES });
  await router.push(`/terminal/sessions/${ticket}`);
  const wrapper = mount(TerminalPage, { global: { plugins: [pinia, router] } });
  await flushAll();
  return wrapper;
}

beforeEach(() => {
  sockets.length = 0;
  mocked.FakeTerminal.last = null;
  vi.stubGlobal('WebSocket', FakeWebSocketImpl);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  mocked.FakeTerminal.last = null;
});

describe('terminal page（M5T4）', () => {
  it('挂载即按 ticket 建立同源 WS 并把二进制帧写入 xterm', async () => {
    const wrapper = await mountPage('ticket-abc');

    expect(sockets).toHaveLength(1);
    const socket = sockets[0]!;
    const expected = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}${apiBaseUrl()}/terminal/sessions/ticket-abc`;
    expect(socket.url).toBe(expected);
    expect(socket.binaryType).toBe('arraybuffer');
    // ready -> open；设备字节流 -> xterm（内容只进终端，不进页面状态）
    emitText(socket, { type: 'ready', session_id: 's-1', protocol: 'ssh' });
    emitBytes(socket, new TextEncoder().encode('display version\r\n'));
    emitBytes(socket, new TextEncoder().encode('VRP (R) software'));
    await flushAll();

    expect(mocked.FakeTerminal.last).not.toBeNull();
    const written = mocked.FakeTerminal.last!.written;
    expect(written.some((chunk) => chunk instanceof Uint8Array)).toBe(true);
    expect(wrapper.text()).toContain('已连接');
  });

  it('ready 后 close 按钮调用 POST close；closed 帧显示中文原因', async () => {
    const fetches: Array<{ url: string; init?: RequestInit }> = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
        fetches.push({ url: String(url), init });
        if (String(url).endsWith('/terminal/sessions/s-1/close')) {
          return jsonResponse({ session_id: 's-1', status: 'closed', close_reason: 'user_closed' });
        }
        return jsonResponse({}, 404);
      }),
    );
    const wrapper = await mountPage();
    const socket = sockets[0]!;
    emitText(socket, { type: 'ready', session_id: 's-1', protocol: 'ssh' });
    await flushAll();

    await wrapper.get('[data-testid="terminal-close"]').trigger('click');
    await flushAll();

    expect(fetches).toHaveLength(1);
    expect(String(fetches[0]!.url)).toContain('/terminal/sessions/s-1/close');
    expect(String(fetches[0]!.init?.method)).toBe('POST');

    emitText(socket, { type: 'closed', reason: 'max_duration' });
    await flushAll();
    expect(wrapper.text()).toContain('会话达到最长时限');
  });

  it('refused 帧（post-accept 拒绝契约）按 reason 渲染对应中文提示', async () => {
    for (const [reason, snippet] of [
      ['ticket_unavailable', '终端票据不可用'],
      ['capacity_user', '会话数量已达上限'],
      ['capacity_device', '会话数量已达上限'],
      ['handshake_failed', '握手失败'],
      ['internal_error', '会话异常终止'],
      ['password_change_required', '先修改密码'],
    ] as const) {
      const wrapper = await mountPage();
      const socket = sockets[sockets.length - 1]!;
      // 服务端：refused 帧先到，随后以同一 code 关闭；状态已 closed 的
      // onClose 不再覆盖具体文案。
      emitText(socket, { type: 'refused', code: 4404, reason, protocol: 'ssh' });
      socket.onclose?.({ code: 4404, reason: '' } as CloseEvent);
      await flushAll();
      expect(wrapper.text()).toContain(snippet);
    }
  });

  it('refused 帧丢失时按关闭码兜底（回退路径仍映射具体中文）', async () => {
    for (const [code, snippet] of [
      [4404, '终端票据不可用'],
      [4429, '会话数量已达上限'],
      [4101, '握手失败'],
    ] as const) {
      const wrapper = await mountPage();
      sockets[sockets.length - 1]!.onclose?.({ code, reason: '' } as CloseEvent);
      await flushAll();
      expect(wrapper.text()).toContain(snippet);
    }
  });

  it('Telnet 会话显示持久弱协议横幅', async () => {
    const wrapper = await mountPage();
    const socket = sockets[0]!;
    emitText(socket, { type: 'ready', session_id: 's-2', protocol: 'telnet' });
    await flushAll();

    expect(wrapper.find('[data-testid="terminal-telnet-warning"]').exists()).toBe(true);
    expect(wrapper.text()).toContain('明文弱协议');
    // SSH 会话不显示该横幅
  });

  it('SSH 会话不显示 Telnet 横幅', async () => {
    const wrapper = await mountPage();
    emitText(sockets[0]!, { type: 'ready', session_id: 's-3', protocol: 'ssh' });
    await flushAll();
    expect(wrapper.find('[data-testid="terminal-telnet-warning"]').exists()).toBe(false);
  });

  it('二进制终端内容不出现在页面状态文本中（正文不进入 UI 状态）', async () => {
    const wrapper = await mountPage();
    emitBytes(sockets[0]!, new TextEncoder().encode('CORE-SECRET-输出内容'));
    await flushAll();
    expect(wrapper.text()).not.toContain('CORE-SECRET');
  });
});
