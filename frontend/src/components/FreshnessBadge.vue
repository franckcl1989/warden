<script setup lang="ts">
import { ElTag } from 'element-plus';

import { FRESHNESS_LABELS, label } from '@/lib/labels';
import { formatDateTime } from '@/lib/format';

// 数据新鲜度徽标（PRODUCT_DESIGN §6.3，UI_SPEC §4 FreshnessBadge）。
// 不支持的指标属于能力支持状态，不走新鲜度徽标。
const props = defineProps<{
  freshness: string | null | undefined;
  observedAt?: string | null;
}>();

const tagType = (): 'success' | 'warning' | 'danger' | 'info' => {
  if (props.freshness === 'fresh') return 'success';
  if (props.freshness === 'stale') return 'warning';
  if (props.freshness === 'expired') return 'danger';
  return 'info';
};
</script>

<template>
  <span class="freshness-badge">
    <el-tag :type="tagType()" size="small">{{ label(FRESHNESS_LABELS, freshness) }}</el-tag>
    <span v-if="observedAt" class="freshness-badge__time">
      {{ formatDateTime(observedAt) }}
    </span>
  </span>
</template>

<style scoped>
.freshness-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.freshness-badge__time {
  color: var(--warden-status-unknown);
  font-size: 12px;
  white-space: nowrap;
}
</style>
