<script setup lang="ts">
/**
 * 浏览器终端页（M5T4，PLT-09 终端部分，ADR-007/API_CONTRACT.md §7）。
 *
 * 进入本页即用路由参数 ticket 建立 WebSocket 连接（同源 Cookie 认证、
 * Origin 由服务端校验）：二进制帧是终端字节流（直接写入 xterm），文本帧
 * 是控制消息（ready / refused / closed / resize）。会话最长 2 小时、空闲
 * 15 分钟由服务端强制断开（closed 帧带机器原因）；Telnet 会话始终显示持久
 * 弱协议横幅。终端内容绝不落日志/数据库（SECURITY.md §8）——本组件也不做
 * 任何内容持久化。
 *
 * 拒绝契约（M5T4 review）：服务端先 accept 再校验票据/门禁/拨号；失败时先
 * 送一个机器 refused 帧（携带 reason 键 + code 关闭码 4000-4999），随后以
 * 该码关闭——本组件按 refused.reason 显示具体中文，关闭码在帧丢失时兜底。
 * Origin/会话等 HTTP 层校验仍在 accept 前，表现为握手失败（error + close
 * 1006），走通用失败文案。
 */
import { FitAddon } from '@xterm/addon-fit';
import { Terminal } from '@xterm/xterm';
import '@xterm/xterm/css/xterm.css';
import { ElButton } from 'element-plus';
import { computed, nextTick, onBeforeUnmount, onMounted, ref, shallowRef } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import { apiBaseUrl, isApiError, request } from '@/api/client';
import {
  closeReasonMessage,
  handshakeCodeMessage,
  refusalReasonMessage,
} from '@/features/terminal/messages';

type SessionState = 'connecting' | 'open' | 'closed';

const route = useRoute();
const router = useRouter();

const ticket = computed(() => String(route.params['ticket'] ?? ''));
const state = ref<SessionState>('connecting');
const protocol = ref<'ssh' | 'telnet' | ''>('');
const sessionId = ref('');
const statusText = ref('');
const closedReason = ref('');
const wsError = ref<string | null>(null);

const termHost = ref<HTMLDivElement | null>(null);
const term = shallowRef<Terminal | null>(null);
const fitAddon = shallowRef<FitAddon | null>(null);
let socket: WebSocket | null = null;
let disposed = false;

const isTelnet = computed(() => protocol.value === 'telnet');
const isOpen = computed(() => state.value === 'open');

function wsUrl(): string {
  const base = apiBaseUrl();
  const path = `${base}/terminal/sessions/${encodeURIComponent(ticket.value)}`;
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${window.location.host}${path}`;
}

function renderChunk(data: ArrayBuffer | Blob): void {
  const terminal = term.value;
  if (terminal === null) {
    return;
  }
  if (data instanceof ArrayBuffer) {
    terminal.write(new Uint8Array(data));
    return;
  }
  void data.arrayBuffer().then((buffer) => {
    if (!disposed) {
      terminal.write(new Uint8Array(buffer));
    }
  });
}

function handleControl(payload: unknown): void {
  if (typeof payload !== 'object' || payload === null) {
    return;
  }
  const control = payload as {
    type?: unknown;
    session_id?: unknown;
    protocol?: unknown;
    reason?: unknown;
    code?: unknown;
  };
  if (control.type === 'ready') {
    sessionId.value = String(control.session_id ?? '');
    protocol.value = control.protocol === 'telnet' ? 'telnet' : control.protocol === 'ssh' ? 'ssh' : '';
    state.value = 'open';
    statusText.value = '';
  } else if (control.type === 'closed') {
    const reason = String(control.reason ?? '');
    closedReason.value = reason;
    statusText.value = closeReasonMessage(reason);
    state.value = 'closed';
  } else if (control.type === 'refused') {
    // 会话从未建立：拒绝帧先于关闭码到达（reason 是权威机器键，code 兜底）。
    const reason = String(control.reason ?? '');
    const code = typeof control.code === 'number' ? control.code : 1006;
    closedReason.value = reason;
    statusText.value =
      refusalReasonMessage(reason) ?? (handshakeCodeMessage(code) || '终端连接被拒绝，请稍后重试。');
    state.value = 'closed';
  }
}

function closeByCode(code: number): void {
  state.value = 'closed';
  statusText.value = '';
  wsError.value = handshakeCodeMessage(code);
}

function onMessage(event: MessageEvent<string | ArrayBuffer | Blob>): void {
  if (typeof event.data === 'string') {
    try {
      handleControl(JSON.parse(event.data) as unknown);
    } catch {
      // 忽略无法解析的控制帧（内容不应出现在文本帧里）
    }
    return;
  }
  renderChunk(event.data);
}

function onClose(event: CloseEvent): void {
  if (disposed || state.value === 'closed') {
    return;
  }
  if (event.code !== 1000) {
    closeByCode(event.code);
  } else {
    state.value = 'closed';
  }
}

function sendResize(): void {
  if (socket === null || socket.readyState !== WebSocket.OPEN) {
    return;
  }
  const terminal = term.value;
  const fit = fitAddon.value;
  if (terminal === null || fit === null) {
    return;
  }
  fit.fit();
  socket.send(JSON.stringify({ type: 'resize', cols: terminal.cols, rows: terminal.rows }));
}

async function closeSession(): Promise<void> {
  if (sessionId.value === '' || state.value !== 'open') {
    void router.push({ name: 'overview' });
    return;
  }
  try {
    await request(`/terminal/sessions/${sessionId.value}/close`, { method: 'POST' });
  } catch (error) {
    if (!isApiError(error)) {
      return;
    }
    // 404（会话已结束）也视为已关闭
  }
}

onMounted(async () => {
  const host = termHost.value;
  if (host === null) {
    return;
  }
  const terminal = new Terminal({
    cursorBlink: true,
    fontFamily: 'Consolas, "Courier New", monospace',
    fontSize: 14,
    scrollback: 2000,
    convertEol: true,
  });
  const fit = new FitAddon();
  terminal.loadAddon(fit);
  terminal.open(host);
  fit.fit();
  term.value = terminal;
  fitAddon.value = fit;
  window.addEventListener('resize', sendResize);

  statusText.value = '正在连接设备…';
  socket = new WebSocket(wsUrl());
  socket.binaryType = 'arraybuffer';
  socket.onmessage = onMessage;
  socket.onclose = onClose;
  socket.onerror = () => {
    wsError.value = '无法建立终端连接，请检查网络后重试';
  };
  await nextTick();
  sendResize();
});

onBeforeUnmount(() => {
  disposed = true;
  window.removeEventListener('resize', sendResize);
  socket?.close();
  socket = null;
  term.value?.dispose();
  term.value = null;
});
</script>

<template>
  <div class="terminal-page" data-testid="terminal-page">
    <header class="terminal-page__header">
      <span class="terminal-page__state" data-testid="terminal-state">
        <template v-if="state === 'connecting'">连接中…</template>
        <template v-else-if="state === 'open'">已连接</template>
        <template v-else>已断开</template>
      </span>
      <span v-if="state === 'open'" class="terminal-page__hint">
        会话最长 2 小时、空闲 15 分钟自动断开；终端内容不会被记录
      </span>
      <el-button
        v-if="isOpen"
        size="small"
        data-testid="terminal-close"
        @click="closeSession"
      >
        关闭会话
      </el-button>
    </header>

    <div v-if="isTelnet" class="terminal-page__warning" data-testid="terminal-telnet-warning">
      Telnet 为明文弱协议：凭据与键盘内容不经加密传输，仅建议在受控管理网内使用。
    </div>

    <p v-if="state === 'closed'" class="terminal-page__ended" data-testid="terminal-ended">
      {{ statusText || wsError || '会话已结束' }}
    </p>

    <div ref="termHost" class="terminal-page__host" data-testid="terminal-host" />
  </div>
</template>

<style scoped>
.terminal-page {
  display: flex;
  flex-direction: column;
  min-height: 480px;
}
.terminal-page__header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 8px;
  font-size: 13px;
}
.terminal-page__state {
  font-weight: 600;
}
.terminal-page__hint {
  color: var(--warden-status-unknown);
  font-size: 12px;
}
.terminal-page__warning {
  background: #fff7e6;
  border: 1px solid #ffd591;
  color: #ad6800;
  padding: 8px 10px;
  font-size: 13px;
  margin-bottom: 8px;
}
.terminal-page__ended {
  color: var(--warden-status-critical);
  margin: 0 0 8px;
  font-size: 13px;
}
.terminal-page__host {
  flex: 1;
  min-height: 360px;
  background: #101418;
  padding: 6px;
  border-radius: 4px;
}
.terminal-page__host :deep(.xterm) {
  height: 100%;
}
</style>
