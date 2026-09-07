<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';

import { request } from '@/api/client';
import type { SystemStatusResponse } from '@/api/types';
import { registerCacheEntry } from '@/lib/query-cache';

// 顶栏系统状态指示（UI_SPEC §2：顶栏显示系统依赖严重状态；仅管理员可见 —
// system.read 为管理员权限，SECURITY §3.1）。规则（M6T3b 决策）：
// 维护模式开启 → 红色“维护模式”；任一组件 degraded/stopped/unavailable →
// 琥珀色“系统异常”；否则不显示。点击进入 /system。
// 刷新来源：SSE system.status_changed / reset / 轮询（query-cache kind
// 'system'，与 /system 页共用失效信号，chip 用独立 id 条目避免互相覆盖）。
const router = useRouter();

type ChipLevel = 'maintenance' | 'degraded';

const level = ref<ChipLevel | null>(null);
const detail = ref('');

async function load(): Promise<void> {
  try {
    const status = await request<SystemStatusResponse>('/system/status');
    level.value = systemChipLevel(status);
    detail.value = systemChipDetail(status);
  } catch {
    // 取不到状态（数据库不可用等）时不显示假芯片：保持隐藏，SSE/轮询会重试。
    level.value = null;
  }
}

function systemChipLevel(status: SystemStatusResponse): ChipLevel | null {
  if (status.maintenance.active) {
    return 'maintenance';
  }
  const components = status.components;
  const degraded =
    components.database.status !== 'ok' ||
    components.file_storage.status !== 'ok' ||
    components.worker.status !== 'ok' ||
    components.ingest.status !== 'ok';
  return degraded ? 'degraded' : null;
}

function systemChipDetail(status: SystemStatusResponse): string {
  if (status.maintenance.active) {
    return status.maintenance.reason ? `维护模式：${status.maintenance.reason}` : '维护模式';
  }
  const parts: string[] = [];
  const bad = (value: string): boolean => value !== 'ok';
  if (bad(status.components.database.status)) parts.push('数据库');
  if (bad(status.components.file_storage.status)) parts.push('文件存储');
  if (bad(status.components.worker.status)) parts.push('Worker');
  if (bad(status.components.ingest.status)) parts.push('事件接收器');
  return parts.length > 0 ? `系统异常：${parts.join('、')}` : '';
}

const chipText = computed(() => (level.value === 'maintenance' ? '维护模式' : detail.value));

let unregister: (() => void) | null = null;

onMounted(() => {
  void load();
  unregister = registerCacheEntry({
    kind: 'system',
    id: 'top-bar',
    refetch: () => void load(),
  });
});

onBeforeUnmount(() => {
  unregister?.();
});

function goSystem(): void {
  void router.push({ name: 'system' });
}
</script>

<template>
  <button
    v-if="level !== null"
    type="button"
    class="system-chip"
    :class="`system-chip--${level}`"
    :title="detail"
    data-testid="system-status-chip"
    @click="goSystem"
  >
    {{ chipText }}
  </button>
</template>

<style scoped>
.system-chip {
  border: none;
  cursor: pointer;
  font-size: 12px;
  border-radius: 10px;
  padding: 2px 10px;
  color: #fff;
}
.system-chip--maintenance {
  background: var(--warden-status-critical);
}
.system-chip--degraded {
  background: var(--warden-status-warning);
}
</style>
