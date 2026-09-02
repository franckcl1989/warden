<script setup lang="ts">
import type { OperationEventView } from '@/api/types';
import { OPERATION_STATE_LABELS, label } from '@/lib/labels';
import { formatDateTimeSeconds } from '@/lib/format';

// UI_SPEC §8 任务时间线：区分"平台已接收 / 已发送设备 / 等待设备 / 验证 / 终态"。
// 阶段归类按事件携带的任务状态映射（M2T4 起每个状态迁移都会写入一条事件）。
const props = defineProps<{
  events: OperationEventView[];
}>();

const PHASE_LABELS: Record<string, string> = {
  queued: '平台已接收',
  running: '已发送设备并执行',
  waiting_device: '等待设备',
  verification_required: '结果验证',
  succeeded: '终态：成功',
  failed: '终态：失败',
  timed_out: '终态：超时',
  cancelled: '终态：已取消',
};

function phase(event: OperationEventView): string {
  return PHASE_LABELS[event.state] ?? label(OPERATION_STATE_LABELS, event.state);
}

function phaseClass(event: OperationEventView): string {
  switch (event.state) {
    case 'succeeded':
      return 'operation-timeline__item--success';
    case 'failed':
    case 'timed_out':
      return 'operation-timeline__item--critical';
    case 'cancelled':
      return 'operation-timeline__item--cancelled';
    case 'verification_required':
      return 'operation-timeline__item--verification';
    default:
      return 'operation-timeline__item--running';
  }
}
</script>

<template>
  <ol v-if="props.events.length > 0" class="operation-timeline" data-testid="operation-timeline">
    <li
      v-for="event in props.events"
      :key="event.id"
      class="operation-timeline__item"
      :class="phaseClass(event)"
    >
      <span class="operation-timeline__rail" :aria-hidden="true" />
      <div class="operation-timeline__body">
        <div class="operation-timeline__head">
          <span class="operation-timeline__phase">{{ phase(event) }}</span>
          <span class="operation-timeline__state">
            {{ label(OPERATION_STATE_LABELS, event.state) }}
          </span>
          <span class="operation-timeline__time">
            {{ formatDateTimeSeconds(event.occurred_at) }}
          </span>
        </div>
        <p class="operation-timeline__message">{{ event.message || '—' }}</p>
        <p class="operation-timeline__meta">
          <span v-if="event.step">步骤：{{ event.step }}</span>
          <span v-if="event.progress_percent !== null && event.progress_percent !== undefined">
            进度：{{ event.progress_percent }}%
          </span>
          <span v-if="event.device_job_id">设备作业：{{ event.device_job_id }}</span>
        </p>
      </div>
    </li>
  </ol>
  <p v-else class="operation-timeline__empty">任务尚未产生时间线记录</p>
</template>

<style scoped>
.operation-timeline {
  list-style: none;
  margin: 0;
  padding: 0;
}
.operation-timeline__item {
  position: relative;
  display: flex;
  gap: 14px;
  padding: 10px 0 10px 4px;
}
.operation-timeline__rail {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  margin-top: 5px;
  background: var(--warden-status-running);
  flex-shrink: 0;
}
.operation-timeline__item--success .operation-timeline__rail {
  background: var(--warden-status-healthy);
}
.operation-timeline__item--critical .operation-timeline__rail {
  background: var(--warden-status-critical);
}
.operation-timeline__item--cancelled .operation-timeline__rail {
  background: var(--warden-status-unknown);
}
.operation-timeline__item--verification .operation-timeline__rail {
  background: var(--warden-status-verification);
}
.operation-timeline__body {
  flex: 1;
  min-width: 0;
  border-bottom: 1px solid var(--el-border-color-lighter);
  padding-bottom: 10px;
}
.operation-timeline__item:last-child .operation-timeline__body {
  border-bottom: none;
}
.operation-timeline__head {
  display: flex;
  align-items: center;
  gap: 10px;
}
.operation-timeline__phase {
  font-weight: 600;
  font-size: 13px;
}
.operation-timeline__state {
  color: var(--warden-status-unknown);
  font-size: 12px;
}
.operation-timeline__time {
  margin-left: auto;
  color: var(--warden-status-unknown);
  font-size: 12px;
  white-space: nowrap;
}
.operation-timeline__message {
  margin: 4px 0 2px;
  font-size: 13px;
}
.operation-timeline__meta {
  margin: 0;
  color: var(--warden-status-unknown);
  font-size: 12px;
  display: flex;
  gap: 14px;
  flex-wrap: wrap;
}
.operation-timeline__empty {
  color: var(--warden-status-unknown);
  font-size: 13px;
}
</style>
