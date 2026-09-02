/**
 * SSE 实时层（M2T7，PLT-09 实时通道页面载体）。
 *
 * UI_SPEC §11 / API_CONTRACT.md §10：GET /events/stream（同源会话 Cookie 认证，
 * EventSource 不能带自定义头）。事件类型 device.updated / alert.opened /
 * alert.resolved / alert.updated / operation.updated / system.status_changed；
 * data 只携带 {"entity_id","version"}，页面收到后重取对应 REST 资源。
 *
 * 状态机：
 * - connected：EventSource 打开；
 * - degraded：连接断开。浏览器自动重连的同时，按 UI_SPEC §11 退化为
 *   15 秒轮询（onPollTick 回调由 store 触发已注册页面的重取）；
 * - reconnect 成功后回到 connected 并停止轮询；
 * - `reset` 事件（服务端游标掉出 10 分钟窗口）→ onReset 全量重取信号。
 *
 * Last-Event-ID 由浏览器原生 EventSource 在重连时自动携带并缓冲
 * （后端 events.py：窗口外返回 reset）。
 */
import { apiBaseUrl } from '@/api/client';

export type RealtimeConnectionState = 'connected' | 'degraded' | 'stopped';

export const POLL_FALLBACK_INTERVAL_MS = 15_000;

export const SSE_EVENT_TYPES = [
  'device.updated',
  'alert.opened',
  'alert.resolved',
  'alert.updated',
  'operation.updated',
  'system.status_changed',
] as const;

export type SseEventType = (typeof SSE_EVENT_TYPES)[number];

export interface SseHandlers {
  /** 某个事件类型到达（entity_id 对应当前变动的资源）。 */
  onEvent: (type: SseEventType, entityId: string | null) => void;
  /** SSE 游标失效：需要全量重取 REST。 */
  onReset: () => void;
  /** 降级轮询周期到点（degraded 状态下每 15 秒一次）。 */
  onPollTick: () => void;
  /** 连接状态变化（connected/degraded）。 */
  onStateChange: (state: RealtimeConnectionState) => void;
}

export interface RealtimeSubscription {
  readonly state: RealtimeConnectionState;
  close: () => void;
}

function isSseEventType(value: string | null): value is SseEventType {
  return value !== null && (SSE_EVENT_TYPES as readonly string[]).includes(value);
}

interface ParsedData {
  entity_id?: string | null;
}

export function subscribeEvents(handlers: SseHandlers): RealtimeSubscription {
  let state: RealtimeConnectionState = 'stopped';
  let source: EventSource | null = null;
  let pollTimer: ReturnType<typeof setInterval> | null = null;

  function setState(next: RealtimeConnectionState): void {
    if (state === next) {
      return;
    }
    state = next;
    handlers.onStateChange(next);
  }

  function stopPolling(): void {
    if (pollTimer !== null) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  function startPolling(): void {
    if (pollTimer !== null) {
      return;
    }
    pollTimer = setInterval(() => {
      handlers.onPollTick();
    }, POLL_FALLBACK_INTERVAL_MS);
  }

  function handleReset(): void {
    handlers.onReset();
  }

  function attach(source: EventSource): void {
    source.addEventListener('open', () => {
      stopPolling();
      setState('connected');
    });
    source.addEventListener('error', () => {
      // EventSource 会自动重连；期间降级为轮询（UI_SPEC §11）
      setState('degraded');
      startPolling();
    });
    for (const type of SSE_EVENT_TYPES) {
      source.addEventListener(type, (event) => {
        let parsed: ParsedData = {};
        try {
          const body: unknown = JSON.parse((event as MessageEvent).data as string);
          if (typeof body === 'object' && body !== null) {
            const { entity_id } = body as ParsedData;
            parsed = { entity_id: entity_id ?? null };
          }
        } catch {
          parsed = {};
        }
        if (isSseEventType(type)) {
          handlers.onEvent(type, parsed.entity_id ?? null);
        }
      });
    }
    source.addEventListener('reset', () => {
      handleReset();
    });
  }

  function connect(): void {
    stopPolling();
    const next = new EventSource(`${apiBaseUrl()}/events/stream`);
    attach(next);
    source = next;
  }

  function close(): void {
    stopPolling();
    if (source !== null) {
      source.close();
      source = null;
    }
    setState('stopped');
  }

  // 环境不支持 EventSource（如部分测试环境）时保持关闭状态，不抛异常
  if (typeof EventSource === 'undefined') {
    return {
      get state() {
        return state;
      },
      close,
    };
  }

  connect();
  return {
    get state() {
      return state;
    },
    close,
  };
}
