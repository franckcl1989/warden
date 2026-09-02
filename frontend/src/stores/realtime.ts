/**
 * 实时状态 store（M2T7）：持有 SSE 连接并把它桥接到页面查询缓存。
 *
 * 事件 → 失效映射（M2T7 决策，对应 UI_SPEC §11）：
 * - operation.updated(entity_id) → 操作列表 + 当前查看的任务详情 + 总览；
 * - alert.opened/resolved/updated(entity_id) → 当前问题 + 总览；
 * - device.updated(entity_id) → 设备列表 + 对应设备详情；
 * - system.status_changed → 系统状态页（M2T8 落地，当前无注册方则无操作）；
 * - reset / 降级轮询到点 → 全量重取（页面缓存只保存重取闭包）。
 *
 * 生命周期由 AppShell 驱动：会话建立后 start，登出/会话失效时 stop。
 * 多实例由单例 store + 订阅句柄保证。
 */
import { ref } from 'vue';
import { defineStore } from 'pinia';

import {
  POLL_FALLBACK_INTERVAL_MS,
  subscribeEvents,
  type RealtimeConnectionState,
  type RealtimeSubscription,
  type SseEventType,
} from '@/api/events';
import { invalidateAllCache, invalidateCache, invalidateCacheById } from '@/lib/query-cache';

export const useRealtimeStore = defineStore('realtime', () => {
  const connectionState = ref<RealtimeConnectionState>('stopped');
  const degradedSince = ref<string | null>(null);
  let subscription: RealtimeSubscription | null = null;

  function handleEvent(type: SseEventType, entityId: string | null): void {
    switch (type) {
      case 'operation.updated':
        invalidateCache('operations');
        if (entityId !== null) {
          invalidateCacheById('operation-detail', entityId);
        }
        invalidateCache('overview');
        break;
      case 'alert.opened':
      case 'alert.resolved':
      case 'alert.updated':
        invalidateCache('alerts');
        invalidateCache('overview');
        break;
      case 'device.updated':
        invalidateCache('devices');
        if (entityId !== null) {
          invalidateCacheById('device-detail', entityId);
        }
        break;
      case 'system.status_changed':
        invalidateCache('system');
        break;
    }
  }

  function onReset(): void {
    invalidateAllCache();
  }

  function onPollTick(): void {
    // UI_SPEC §11：断开期间 15 秒轮询当前页面数据（只触发已注册的重取闭包）
    invalidateAllCache();
  }

  function start(): void {
    if (subscription !== null) {
      return;
    }
    subscription = subscribeEvents({
      onEvent: handleEvent,
      onReset,
      onPollTick,
      onStateChange: (next) => {
        connectionState.value = next;
        if (next === 'degraded') {
          degradedSince.value = new Date().toISOString();
        } else if (next === 'connected') {
          degradedSince.value = null;
        }
      },
    });
    connectionState.value = subscription.state;
  }

  function stop(): void {
    subscription?.close();
    subscription = null;
    connectionState.value = 'stopped';
    degradedSince.value = null;
  }

  return {
    connectionState,
    degradedSince,
    pollFallbackIntervalMs: POLL_FALLBACK_INTERVAL_MS,
    start,
    stop,
  };
});
