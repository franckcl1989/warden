<script setup lang="ts">
import SeverityBadge from '@/components/SeverityBadge.vue';
import type { DeviceEventView } from '@/api/types';
import { formatDateTimeSeconds } from '@/lib/format';

// UI_SPEC §4 EventTimeline：设备事件时间线（SEL/DSM 日志/Trap/Syslog）。
// 事件是时间点历史，不自动变成当前告警（PRODUCT_DESIGN §6.4）。
defineProps<{
  events: DeviceEventView[];
}>();
</script>

<template>
  <ol class="event-timeline" data-testid="event-timeline">
    <li v-for="event in events" :key="event.id" class="event-timeline__item">
      <div class="event-timeline__rail">
        <span class="event-timeline__dot" :aria-hidden="true" />
      </div>
      <div class="event-timeline__body">
        <div class="event-timeline__head">
          <SeverityBadge :severity="event.severity" mode="event" />
          <span class="event-timeline__type">{{ event.event_type }}</span>
          <span class="event-timeline__time">{{ formatDateTimeSeconds(event.occurred_at) }}</span>
        </div>
        <p class="event-timeline__message">{{ event.message || '—' }}</p>
        <p class="event-timeline__meta">
          <span v-if="event.component_id">组件：{{ event.component_id }}</span>
          <span>来源：{{ event.source }}</span>
          <span v-if="event.native_event_id">设备事件 ID：{{ event.native_event_id }}</span>
        </p>
      </div>
    </li>
  </ol>
</template>

<style scoped>
.event-timeline {
  list-style: none;
  margin: 0;
  padding: 0;
}
.event-timeline__item {
  display: flex;
  gap: 12px;
  padding: 10px 0;
  border-bottom: 1px solid var(--el-border-color-lighter);
}
.event-timeline__rail {
  display: flex;
  justify-content: center;
  padding-top: 6px;
}
.event-timeline__dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--warden-status-unknown);
}
.event-timeline__body {
  flex: 1;
  min-width: 0;
}
.event-timeline__head {
  display: flex;
  align-items: center;
  gap: 10px;
}
.event-timeline__type {
  font-family: monospace;
  font-size: 13px;
}
.event-timeline__time {
  margin-left: auto;
  color: var(--warden-status-unknown);
  font-size: 12px;
  white-space: nowrap;
}
.event-timeline__message {
  margin: 6px 0 4px;
  font-size: 14px;
}
.event-timeline__meta {
  margin: 0;
  color: var(--warden-status-unknown);
  font-size: 12px;
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
}
</style>
