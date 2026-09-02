<script setup lang="ts">
import { ElOption, ElSelect } from 'element-plus';
import { onMounted, ref, watch } from 'vue';

import AsyncState from '@/components/AsyncState.vue';
import EventTimeline from '@/components/EventTimeline.vue';
import PaginationBar from '@/components/PaginationBar.vue';
import type { ApiError } from '@/api/client';
import { request } from '@/api/client';
import type { CapabilityView, DeviceEventView, DeviceEventsListResponse } from '@/api/types';
import { EVENT_SEVERITY_LABELS, label } from '@/lib/labels';
import { listQueryString } from './common';

// 设备事件页签（PLT-03）：SEL/DSM 日志/Trap/Syslog 等时间点事实，
// 支持 severity/event_type 过滤（PRODUCT_DESIGN §6.4：事件不自动成为当前问题）。
const props = defineProps<{
  deviceId: string;
  eventTypes?: string[];
  capabilities: CapabilityView[];
}>();

const SEVERITY_OPTIONS = ['unknown', 'info', 'warning', 'critical'];

const state = ref<'loading' | 'ready' | 'empty' | 'error' | 'permission_denied'>('loading');
const error = ref<ApiError | null>(null);
const response = ref<DeviceEventsListResponse | null>(null);
const severityFilter = ref<string | null>(null);
const eventTypeFilter = ref<string | null>(null);
const page = ref(1);
const pageSize = ref(20);

function eventTypeOptions(): string[] {
  const fromCaps = new Set<string>();
  for (const capability of props.capabilities) {
    if (capability.capability_key.startsWith('event.')) {
      fromCaps.add(capability.capability_key);
    }
  }
  for (const eventType of props.eventTypes ?? []) {
    fromCaps.add(eventType);
  }
  return [...fromCaps];
}

async function load(): Promise<void> {
  state.value = 'loading';
  error.value = null;
  try {
    const query = listQueryString({
      page: page.value,
      page_size: pageSize.value,
      severity: severityFilter.value,
      event_type: eventTypeFilter.value ?? props.eventTypes?.[0] ?? null,
    });
    const result = await request<DeviceEventsListResponse>(
      `/devices/${props.deviceId}/events?${query}`,
    );
    response.value = result;
    state.value = result.total === 0 ? 'empty' : 'ready';
  } catch (caught) {
    error.value = caught as ApiError;
    state.value = error.value.code === 'permission_denied' ? 'permission_denied' : 'error';
  }
}

function emptyText(): string {
  if (severityFilter.value !== null || eventTypeFilter.value !== null) {
    return '筛选无结果';
  }
  return '尚无设备事件';
}

function applySeverity(): void {
  page.value = 1;
  void load();
}

function applyEventType(): void {
  page.value = 1;
  void load();
}

function onPageChange(next: number): void {
  page.value = next;
  void load();
}

function onPageSizeChange(size: number): void {
  pageSize.value = size;
  page.value = 1;
  void load();
}

watch(
  () => props.eventTypes,
  () => {
    eventTypeFilter.value = null;
    page.value = 1;
    void load();
  },
);

onMounted(() => {
  void load();
});
</script>

<template>
  <div class="events-panel">
    <div class="events-panel__toolbar">
      <el-select
        v-model="severityFilter"
        placeholder="严重级别"
        clearable
        class="events-panel__filter"
        data-testid="filter-event-severity"
        @change="applySeverity"
      >
        <el-option
          v-for="severity in SEVERITY_OPTIONS"
          :key="severity"
          :value="severity"
          :label="label(EVENT_SEVERITY_LABELS, severity)"
        />
      </el-select>
      <el-select
        v-if="eventTypeOptions().length > 0"
        v-model="eventTypeFilter"
        placeholder="事件类型"
        clearable
        class="events-panel__filter"
        data-testid="filter-event-type"
        @change="applyEventType"
      >
        <el-option
          v-for="eventType in eventTypeOptions()"
          :key="eventType"
          :value="eventType"
          :label="eventType"
        />
      </el-select>
    </div>

    <AsyncState :state="state" :error="error" :empty-text="emptyText()" @retry="load">
      <EventTimeline
        v-if="(response?.items ?? []).length > 0"
        :events="(response?.items ?? []) as DeviceEventView[]"
      />
      <PaginationBar
        v-model:page="page"
        v-model:page-size="pageSize"
        :total="response?.total ?? 0"
        @update:page="onPageChange"
        @update:page-size="onPageSizeChange"
      />
    </AsyncState>
  </div>
</template>

<style scoped>
.events-panel__toolbar {
  display: flex;
  gap: 8px;
  margin-bottom: 12px;
}
.events-panel__filter {
  width: 180px;
}
</style>
