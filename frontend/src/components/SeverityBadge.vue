<script setup lang="ts">
import { ElTag } from 'element-plus';

import { ALERT_SEVERITY_LABELS, EVENT_SEVERITY_LABELS, label } from '@/lib/labels';

// 严重级别徽标（当前问题/设备事件共用）。event 模式含 info 级别。
const props = withDefaults(
  defineProps<{
    severity: string | null | undefined;
    mode?: 'alert' | 'event';
  }>(),
  { mode: 'alert' },
);

const map = (): Record<string, string> =>
  props.mode === 'event' ? EVENT_SEVERITY_LABELS : ALERT_SEVERITY_LABELS;

const tagType = (): 'success' | 'warning' | 'danger' | 'info' => {
  if (props.severity === 'critical') return 'danger';
  if (props.severity === 'warning') return 'warning';
  if (props.mode === 'event' && props.severity === 'info') return 'info';
  return 'info';
};
</script>

<template>
  <el-tag :type="tagType()" size="small">{{ label(map(), severity) }}</el-tag>
</template>
