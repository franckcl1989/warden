<script setup lang="ts">
import { computed } from 'vue';

import FreshnessBadge from '@/components/FreshnessBadge.vue';
import type { LatestMetricItem } from '@/api/types';
import { ENUM_VALUE_LABELS, QUALITY_LABELS, label } from '@/lib/labels';
import { formatMetricValue, unitLabel } from '@/lib/format';

// UI_SPEC §4/§7.3 MetricValue：值 + 单位 + 质量 + 观测时间 + 新鲜度徽标。
// 枚举/布尔值按 contracts 语义展示（可安全直译的值转中文，其余展示原始代码值）。
const props = defineProps<{
  item: LatestMetricItem;
}>();

const displayValue = computed(() => {
  const raw = props.item.value;
  if (raw === null || raw === undefined) {
    return '—';
  }
  if (typeof raw === 'string') {
    return label(ENUM_VALUE_LABELS, raw);
  }
  if (typeof raw === 'boolean') {
    return raw ? '是' : '否';
  }
  return formatMetricValue(raw);
});

const valueClass = computed(() => {
  if (typeof props.item.value === 'string') {
    if (
      ['critical', 'failed', 'detected', 'fault', 'broken', 'low_battery'].includes(
        props.item.value,
      )
    ) {
      return 'metric-value__value--critical';
    }
    if (['warning', 'degraded', 'on_battery', 'communication_lost'].includes(props.item.value)) {
      return 'metric-value__value--warning';
    }
    if (['unknown'].includes(props.item.value)) {
      return 'metric-value__value--unknown';
    }
  }
  return '';
});
</script>

<template>
  <div class="metric-value">
    <div class="metric-value__value-line">
      <span class="metric-value__value" :class="valueClass">{{ displayValue }}</span>
      <span v-if="item.unit" class="metric-value__unit">{{ unitLabel(item.unit) }}</span>
    </div>
    <div class="metric-value__meta">
      <FreshnessBadge :freshness="item.freshness" :observed-at="item.observed_at" />
      <span class="metric-value__quality"> 质量：{{ label(QUALITY_LABELS, item.quality) }} </span>
    </div>
  </div>
</template>

<style scoped>
.metric-value__value-line {
  display: flex;
  align-items: baseline;
  gap: 6px;
}
.metric-value__value {
  font-size: 20px;
  font-weight: 600;
  font-family: monospace;
}
.metric-value__value--critical {
  color: var(--warden-status-critical);
}
.metric-value__value--warning {
  color: var(--warden-status-warning);
}
.metric-value__value--unknown {
  color: var(--warden-status-unknown);
}
.metric-value__unit {
  color: var(--warden-status-unknown);
  font-size: 13px;
}
.metric-value__meta {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-top: 4px;
}
.metric-value__quality {
  color: var(--warden-status-unknown);
  font-size: 12px;
}
</style>
