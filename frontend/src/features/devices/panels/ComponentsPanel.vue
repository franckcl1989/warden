<script setup lang="ts">
import { ElOption, ElSelect } from 'element-plus';
import { onMounted, ref, watch } from 'vue';

import AsyncState from '@/components/AsyncState.vue';
import ComponentTable from '@/components/ComponentTable.vue';
import PaginationBar from '@/components/PaginationBar.vue';
import type { ApiError } from '@/api/client';
import { request } from '@/api/client';
import type { DeviceComponentsListResponse } from '@/api/types';
import { ENUM_VALUE_LABELS, label } from '@/lib/labels';
import { listQueryString } from './common';

// 组件当前态页签（PLT-03 / UI_SPEC §5）：kind/status 过滤由服务端完成。
const props = defineProps<{
  deviceId: string;
  kinds?: string[];
}>();

const state = ref<'loading' | 'ready' | 'empty' | 'error' | 'permission_denied'>('loading');
const error = ref<ApiError | null>(null);
const response = ref<DeviceComponentsListResponse | null>(null);
const kindFilter = ref<string | null>(null);
const statusFilter = ref<string | null>(null);
const page = ref(1);
const pageSize = ref(20);

const KIND_OPTIONS = [
  'processor',
  'memory',
  'drive',
  'disk',
  'fan',
  'psu',
  'interface',
  'transceiver',
  'storage_pool',
  'volume',
  'shared_folder',
];
const STATUS_OPTIONS = [
  'unknown',
  'ok',
  'warning',
  'critical',
  'absent',
  'healthy',
  'degraded',
  'failed',
];

async function load(): Promise<void> {
  state.value = 'loading';
  error.value = null;
  try {
    const query = listQueryString({
      page: page.value,
      page_size: pageSize.value,
      kind: kindFilter.value ?? props.kinds?.[0] ?? null,
      status: statusFilter.value,
    });
    const result = await request<DeviceComponentsListResponse>(
      `/devices/${props.deviceId}/components?${query}`,
    );
    response.value = result;
    state.value = result.total === 0 ? 'empty' : 'ready';
  } catch (caught) {
    error.value = caught as ApiError;
    state.value = error.value.code === 'permission_denied' ? 'permission_denied' : 'error';
  }
}

function emptyText(): string {
  if (statusFilter.value !== null || kindFilter.value !== null) {
    return '筛选无结果';
  }
  return '尚无组件观测数据';
}

function onKindChange(): void {
  page.value = 1;
  void load();
}

function onStatusChange(): void {
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

function hasItems(): boolean {
  return (response.value?.items ?? []).length > 0;
}

function uniqueKinds(): string[] {
  const seen = new Set<string>();
  for (const item of response.value?.items ?? []) {
    seen.add(item.kind);
  }
  for (const kind of props.kinds ?? []) {
    seen.add(kind);
  }
  return [...seen];
}

function selectKindOptions(): string[] {
  const options = uniqueKinds();
  if (options.length === 0) {
    return [...KIND_OPTIONS];
  }
  return options;
}

watch(
  () => props.kinds,
  () => {
    kindFilter.value = null;
    page.value = 1;
    void load();
  },
);

onMounted(() => {
  void load();
});
</script>

<template>
  <div class="components-panel">
    <div class="components-panel__toolbar">
      <el-select
        v-model="kindFilter"
        placeholder="组件类型"
        clearable
        class="components-panel__filter"
        data-testid="filter-component-kind"
        @change="onKindChange"
      >
        <el-option v-for="kind in selectKindOptions()" :key="kind" :value="kind" :label="kind" />
      </el-select>
      <el-select
        v-model="statusFilter"
        placeholder="状态"
        clearable
        class="components-panel__filter"
        data-testid="filter-component-status"
        @change="onStatusChange"
      >
        <el-option
          v-for="status in STATUS_OPTIONS"
          :key="status"
          :value="status"
          :label="label(ENUM_VALUE_LABELS, status)"
        />
      </el-select>
    </div>

    <AsyncState :state="state" :error="error" :empty-text="emptyText()" @retry="load">
      <ComponentTable v-if="hasItems()" :items="response?.items ?? []" />
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
.components-panel__toolbar {
  display: flex;
  gap: 8px;
  margin-bottom: 12px;
}
.components-panel__filter {
  width: 180px;
}
</style>
