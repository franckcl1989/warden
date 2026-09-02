<script setup lang="ts">
import { ElTable, ElTableColumn } from 'element-plus';
import type { ComponentView } from '@/api/types';
import { ENUM_VALUE_LABELS, label } from '@/lib/labels';
import { formatDateTimeSeconds } from '@/lib/format';

// UI_SPEC §4/§5 ComponentTable：组件当前态列表（kind/status/native_id/properties）。
// 分页与筛选由父页面按 API 查询参数完成，本组件只负责渲染。
defineProps<{
  items: ComponentView[];
}>();

function statusType(status: string | null | undefined): 'success' | 'warning' | 'danger' | 'info' {
  if (status === 'ok' || status === 'healthy' || status === 'normal' || status === 'optimal') {
    return 'success';
  }
  if (status === 'warning' || status === 'degraded') {
    return 'warning';
  }
  if (
    status === 'critical' ||
    status === 'failed' ||
    status === 'absent' ||
    status === 'detected' ||
    status === 'broken' ||
    status === 'fault'
  ) {
    return 'danger';
  }
  return 'info';
}

function propertySummary(properties: Record<string, unknown>): string {
  const entries = Object.entries(properties);
  if (entries.length === 0) {
    return '—';
  }
  return entries
    .slice(0, 4)
    .map(([key, value]) => `${key}: ${String(value)}`)
    .join('；');
}
</script>

<template>
  <el-table
    class="component-table"
    :data="items"
    row-key="id"
    data-testid="component-table"
    size="default"
  >
    <el-table-column label="组件" min-width="200">
      <template #default="{ row }">
        <div class="component-table__name">{{ row.name || row.native_id || '—' }}</div>
        <div class="component-table__sub">{{ row.kind }} · {{ row.native_id || '—' }}</div>
      </template>
    </el-table-column>
    <el-table-column label="状态" width="110">
      <template #default="{ row }">
        <span
          class="component-table__status"
          :class="`component-table__status--${statusType(row.status)}`"
        >
          {{ label(ENUM_VALUE_LABELS, row.status) }}
        </span>
      </template>
    </el-table-column>
    <el-table-column label="属性" min-width="280">
      <template #default="{ row }">{{ propertySummary(row.properties ?? {}) }}</template>
    </el-table-column>
    <el-table-column label="首次发现" width="140">
      <template #default="{ row }">{{ formatDateTimeSeconds(row.first_seen_at) }}</template>
    </el-table-column>
    <el-table-column label="最近观测" width="140">
      <template #default="{ row }">{{ formatDateTimeSeconds(row.last_seen_at) }}</template>
    </el-table-column>
  </el-table>
</template>

<style scoped>
.component-table__name {
  font-weight: 600;
}
.component-table__sub {
  color: var(--warden-status-unknown);
  font-size: 12px;
  font-family: monospace;
}
.component-table__status {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 3px;
  font-size: 12px;
  border: 1px solid transparent;
}
.component-table__status--success {
  color: var(--warden-status-healthy);
  border-color: var(--warden-status-healthy);
}
.component-table__status--warning {
  color: var(--warden-status-warning);
  border-color: var(--warden-status-warning);
}
.component-table__status--danger {
  color: var(--warden-status-critical);
  border-color: var(--warden-status-critical);
}
.component-table__status--info {
  color: var(--warden-status-unknown);
  border-color: var(--warden-status-unknown);
}
</style>
