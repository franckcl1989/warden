<script setup lang="ts">
import { ElTag } from 'element-plus';

import { OPERATION_STATE_LABELS, label } from '@/lib/labels';

// 操作任务状态徽标（GLOSSARY/UI_SPEC §8）：
// - queued/running/waiting_device 使用运行蓝；
// - succeeded 绿色；failed/timed_out 红色；cancelled 灰色；
// - verification_required 使用独立紫色（UI_SPEC §3 待核验语义，
//   页面提供"重新回读"而不是"重试操作"）。
const props = defineProps<{ state: string | null | undefined }>();

const tagType = (): 'success' | 'warning' | 'danger' | 'info' | 'primary' => {
  switch (props.state) {
    case 'succeeded':
      return 'success';
    case 'failed':
    case 'timed_out':
      return 'danger';
    case 'cancelled':
      return 'info';
    case 'queued':
    case 'running':
    case 'waiting_device':
      return 'primary';
    default:
      return 'info';
  }
};
</script>

<template>
  <el-tag
    class="operation-state"
    :class="{ 'operation-state--verification': state === 'verification_required' }"
    :type="tagType()"
    size="small"
  >
    {{ label(OPERATION_STATE_LABELS, state) }}
  </el-tag>
</template>

<style scoped>
.operation-state--verification {
  --el-tag-bg-color: color-mix(in srgb, var(--warden-status-verification) 12%, white);
  --el-tag-border-color: var(--warden-status-verification);
  --el-tag-text-color: var(--warden-status-verification);
  color: var(--warden-status-verification);
}
</style>
