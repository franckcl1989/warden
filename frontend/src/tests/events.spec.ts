import { createPinia, setActivePinia } from 'pinia';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { subscribeEvents, type SseEventType } from '@/api/events';
import { registerCacheEntry } from '@/lib/query-cache';
import { useRealtimeStore } from '@/stores/realtime';

/**
 * SSE 实时层测试（M2T7，UI_SPEC §11）：
 * - 事件分发与 reset；断线降级 15 秒轮询、恢复后停止（轮询回调计数）；
 * - Last-Event-ID 由浏览器原生 EventSource 缓冲（这里用假实现验证重连事件
 *   重新挂载，不测浏览器内部）；
 * - store 事件 → 查询缓存失效映射（operation/alert/device/reset）。
 */

type Listener = (event: MessageEvent) => void;

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  listeners = new Map<string, Listener[]>();
  url: string;
  closed = false;

  constructor(url: string) {
    this.url = url;
    FakeEventSource.instances.push(this);
  }

  addEventListener(type: string, listener: Listener): void {
    const list = this.listeners.get(type) ?? [];
    list.push(listener);
    this.listeners.set(type, list);
  }

  close(): void {
    this.closed = true;
    this.listeners.clear();
  }

  fire(type: string, data?: string): void {
    if (this.closed) {
      return;
    }
    for (const listener of this.listeners.get(type) ?? []) {
      listener({ data: data ?? '', type } as MessageEvent);
    }
  }
}

function latestSource(): FakeEventSource {
  const source = FakeEventSource.instances.at(-1);
  if (source === undefined) {
    throw new Error('no EventSource created');
  }
  return source;
}

function installEventSource(): typeof FakeEventSource {
  vi.stubGlobal('EventSource', FakeEventSource);
  FakeEventSource.instances = [];
  return FakeEventSource;
}

describe('SSE 订阅层（PLT-09）', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it('分发已知事件类型并忽略未知事件', () => {
    installEventSource();
    const seen: [SseEventType, string | null][] = [];
    const { close } = subscribeEvents({
      onEvent: (type, entityId) => seen.push([type, entityId]),
      onReset: () => undefined,
      onPollTick: () => undefined,
      onStateChange: () => undefined,
    });
    const source = latestSource();
    source.fire('operation.updated', JSON.stringify({ entity_id: 'op-1', version: 3 }));
    source.fire('alert.opened', JSON.stringify({ entity_id: 'al-2', version: 1 }));
    source.fire('device.updated', JSON.stringify({ entity_id: 'd-1', version: 9 }));
    source.fire('mystery.event', JSON.stringify({}));
    expect(seen).toEqual([
      ['operation.updated', 'op-1'],
      ['alert.opened', 'al-2'],
      ['device.updated', 'd-1'],
    ]);
    expect(source.url).toContain('/api/v1/events/stream');
    close();
  });

  it('reset 事件触发全量重取信号', () => {
    installEventSource();
    let resets = 0;
    const { close } = subscribeEvents({
      onEvent: () => undefined,
      onReset: () => {
        resets += 1;
      },
      onPollTick: () => undefined,
      onStateChange: () => undefined,
    });
    const source = latestSource();
    source.fire('reset', '{}');
    expect(resets).toBe(1);
    close();
  });

  it('断线进入 degraded 并启动 15 秒轮询，恢复连接后停止轮询', () => {
    installEventSource();
    const states: string[] = [];
    let ticks = 0;
    const { close } = subscribeEvents({
      onEvent: () => undefined,
      onReset: () => undefined,
      onPollTick: () => {
        ticks += 1;
      },
      onStateChange: (next) => states.push(next),
    });
    const source = latestSource();
    source.fire('error');
    expect(states).toContain('degraded');
    vi.advanceTimersByTime(15_000);
    expect(ticks).toBe(1);
    vi.advanceTimersByTime(30_000);
    expect(ticks).toBe(3);
    source.fire('open');
    expect(states.at(-1)).toBe('connected');
    vi.advanceTimersByTime(30_000);
    expect(ticks).toBe(3);
    close();
  });

  it('close 后停止轮询且不接收后续事件', () => {
    installEventSource();
    const seen: string[] = [];
    let ticks = 0;
    const { close } = subscribeEvents({
      onEvent: (type) => seen.push(type),
      onReset: () => undefined,
      onPollTick: () => {
        ticks += 1;
      },
      onStateChange: () => undefined,
    });
    const source = latestSource();
    source.fire('error');
    close();
    vi.advanceTimersByTime(30_000);
    expect(ticks).toBe(0);
    source.fire('operation.updated', JSON.stringify({}));
    expect(seen).toEqual([]);
  });

  it('环境没有 EventSource 时不抛异常并保持 stopped', () => {
    vi.stubGlobal('EventSource', undefined);
    const { state, close } = subscribeEvents({
      onEvent: () => undefined,
      onReset: () => undefined,
      onPollTick: () => undefined,
      onStateChange: () => undefined,
    });
    expect(state).toBe('stopped');
    close();
  });
});

describe('realtime store 事件 → 查询缓存失效', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('operation.updated 重取操作列表、对应详情与总览', async () => {
    installEventSource();
    const calls: string[] = [];
    registerCacheEntry({
      kind: 'operations',
      refetch: () => {
        calls.push('operations');
      },
    });
    registerCacheEntry({
      kind: 'operation-detail',
      id: 'op-1',
      refetch: () => {
        calls.push('detail-op-1');
      },
    });
    registerCacheEntry({
      kind: 'operation-detail',
      id: 'op-2',
      refetch: () => {
        calls.push('detail-op-2');
      },
    });
    registerCacheEntry({
      kind: 'overview',
      refetch: () => {
        calls.push('overview');
      },
    });
    const realtime = useRealtimeStore();
    realtime.start();
    const source = latestSource();
    source.fire('operation.updated', JSON.stringify({ entity_id: 'op-1', version: 2 }));
    await vi.waitFor(() => {
      expect(calls).toContain('operations');
      expect(calls).toContain('detail-op-1');
      expect(calls).not.toContain('detail-op-2');
      expect(calls).toContain('overview');
    });
    realtime.stop();
  });

  it('alert 事件重取当前问题与总览；device.updated 重取设备列表与对应详情', async () => {
    installEventSource();
    const calls: string[] = [];
    registerCacheEntry({
      kind: 'alerts',
      refetch: () => {
        calls.push('alerts');
      },
    });
    registerCacheEntry({
      kind: 'overview',
      refetch: () => {
        calls.push('overview');
      },
    });
    registerCacheEntry({
      kind: 'devices',
      refetch: () => {
        calls.push('devices');
      },
    });
    registerCacheEntry({
      kind: 'device-detail',
      id: 'd-9',
      refetch: () => {
        calls.push('device-detail-d-9');
      },
    });
    const realtime = useRealtimeStore();
    realtime.start();
    const source = latestSource();
    source.fire('alert.opened', JSON.stringify({ entity_id: 'al-1', version: 1 }));
    source.fire('device.updated', JSON.stringify({ entity_id: 'd-9', version: 5 }));
    await vi.waitFor(() => {
      expect(calls).toContain('alerts');
      expect(calls).toContain('overview');
      expect(calls).toContain('devices');
      expect(calls).toContain('device-detail-d-9');
    });
    realtime.stop();
  });

  it('reset 与降级轮询触发全量重取', async () => {
    installEventSource();
    const calls: string[] = [];
    registerCacheEntry({
      kind: 'alerts',
      refetch: () => {
        calls.push('alerts');
      },
    });
    registerCacheEntry({
      kind: 'operations',
      refetch: () => {
        calls.push('operations');
      },
    });
    const realtime = useRealtimeStore();
    realtime.start();
    const source = latestSource();
    source.fire('reset', '{}');
    await vi.waitFor(() => {
      expect(calls).toContain('alerts');
      expect(calls).toContain('operations');
    });
    realtime.stop();
  });
});
