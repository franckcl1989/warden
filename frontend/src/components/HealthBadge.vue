<script setup lang="ts">
import { ElTag } from 'element-plus';

import { HEALTH_LABELS, label } from '@/lib/labels';

// 健康徽标（GLOSSARY：health）。离线不覆盖最后已知健康（PRODUCT_DESIGN §6.2）。
const props = defineProps<{
  health: string | null | undefined;
  lastKnownHealth?: string | null;
}>();

const tagType = (): 'success' | 'warning' | 'danger' | 'info' => {
  if (props.health === 'healthy') return 'success';
  if (props.health === 'warning') return 'warning';
  if (props.health === 'critical') return 'danger';
  return 'info';
};

const lastKnown = (): string | null => {
  const last = props.lastKnownHealth;
  if (last === null || last === undefined || last === props.health) {
    return null;
  }
  return label(HEALTH_LABELS, last);
};
</script>

<template>
  <span class="health-badge">
    <el-tag :type="tagType()" size="small">{{ label(HEALTH_LABELS, health) }}</el-tag>
    <span v-if="lastKnown()" class="health-badge__last">最后已知：{{ lastKnown() }}</span>
  </span>
</template>

<style scoped>
.health-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.health-badge__last {
  color: var(--warden-status-unknown);
  font-size: 12px;
}
</style>
