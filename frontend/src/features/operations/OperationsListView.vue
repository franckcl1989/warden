<script setup lang="ts">
import { ElOption, ElSelect, ElTable, ElTableColumn } from 'element-plus';
import { onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import AsyncState from '@/components/AsyncState.vue';
import OperationState from '@/components/OperationState.vue';
import PaginationBar from '@/components/PaginationBar.vue';
import type { ApiError } from '@/api/client';
import { request } from '@/api/client';
import type { DeviceListResponse, OperationsListResponse, OperationTaskView } from '@/api/types';
import { OPERATION_PROFILE_IDS, REQUIREMENTS } from '@/api/generated/contracts';
import { formatDateTime } from '@/lib/format';
import { OPERATION_STATE_LABELS, label } from '@/lib/labels';
import { registerCacheEntry } from '@/lib/query-cache';

// 操作任务列表（PLT-05）：state/device/requirement/capability 筛选（写入 URL
// query），行点击进入任务详情；SSE operation.updated 时静默刷新。
const route = useRoute();
const router = useRouter();

const stateFilter = ref<string | null>(
  typeof route.query['state'] === 'string' ? String(route.query['state']) : null,
);
const deviceFilter = ref<string | null>(
  typeof route.query['device_id'] === 'string' ? String(route.query['device_id']) : null,
);
const requirementFilter = ref<string | null>(
  typeof route.query['requirement_id'] === 'string' ? String(route.query['requirement_id']) : null,
);
const capabilityFilter = ref<string | null>(
  typeof route.query['capability_key'] === 'string' ? String(route.query['capability_key']) : null,
);
const page = ref(1);
const pageSize = ref(20);

const state = ref<'loading' | 'ready' | 'empty' | 'error' | 'permission_denied'>('loading');
const error = ref<ApiError | null>(null);
const response = ref<OperationsListResponse | null>(null);

const deviceOptions = ref<{ id: string; name: string }[]>([]);

const OPERATION_STATES = [
  'queued',
  'running',
  'waiting_device',
  'succeeded',
  'failed',
  'timed_out',
  'cancelled',
  'verification_required',
];

const requirementOptions = (): string[] =>
  Object.entries(REQUIREMENTS)
    .filter(([, requirement]) => requirement.kind === 'operation')
    .map(([id]) => id);

const capabilityOptions = (): string[] => [
  ...new Set(OPERATION_PROFILE_IDS.map((profileId) => profileId.split(':')[1] ?? '')),
];

async function load(): Promise<void> {
  state.value = 'loading';
  error.value = null;
  try {
    const params = new URLSearchParams({
      page: String(page.value),
      page_size: String(pageSize.value),
    });
    if (stateFilter.value) params.set('state', stateFilter.value);
    if (deviceFilter.value) params.set('device_id', deviceFilter.value);
    if (requirementFilter.value) params.set('requirement_id', requirementFilter.value);
    if (capabilityFilter.value) params.set('capability_key', capabilityFilter.value);
    const result = await request<OperationsListResponse>(`/operations?${params}`);
    response.value = result;
    state.value = result.total === 0 ? 'empty' : 'ready';
  } catch (caught) {
    error.value = caught as ApiError;
    state.value = error.value.code === 'permission_denied' ? 'permission_denied' : 'error';
  }
}

function pushQuery(): void {
  const query = { ...route.query } as Record<string, string | null>;
  for (const [key, value] of [
    ['state', stateFilter.value],
    ['device_id', deviceFilter.value],
    ['requirement_id', requirementFilter.value],
    ['capability_key', capabilityFilter.value],
  ] as const) {
    if (value !== null && value !== undefined) {
      query[key] = value;
    } else {
      delete query[key];
    }
  }
  void router.replace({ query });
}

function applyFilters(): void {
  page.value = 1;
  pushQuery();
}

function clearFilters(): void {
  stateFilter.value = null;
  deviceFilter.value = null;
  requirementFilter.value = null;
  capabilityFilter.value = null;
  page.value = 1;
  pushQuery();
}

watch(
  () =>
    [
      route.query['state'],
      route.query['device_id'],
      route.query['requirement_id'],
      route.query['capability_key'],
    ] as const,
  ([nextState, nextDevice, nextRequirement, nextCapability]) => {
    stateFilter.value = typeof nextState === 'string' ? nextState : null;
    deviceFilter.value = typeof nextDevice === 'string' ? nextDevice : null;
    requirementFilter.value = typeof nextRequirement === 'string' ? nextRequirement : null;
    capabilityFilter.value = typeof nextCapability === 'string' ? nextCapability : null;
    void load();
  },
);

function onPageChange(next: number): void {
  page.value = next;
  void load();
}

function onPageSizeChange(size: number): void {
  pageSize.value = size;
  page.value = 1;
  void load();
}

function openDetail(row: OperationTaskView): void {
  void router.push({ name: 'operations-detail', params: { id: row.id } });
}

function emptyText(): string {
  const hasFilter =
    stateFilter.value !== null ||
    deviceFilter.value !== null ||
    requirementFilter.value !== null ||
    capabilityFilter.value !== null;
  if (hasFilter) {
    return '筛选无结果';
  }
  return '尚无操作任务';
}

let unregister: (() => void) | null = null;

onMounted(() => {
  void load();
  void request<DeviceListResponse>('/devices?page=1&page_size=100')
    .then((result) => {
      deviceOptions.value = (result.items ?? []).map((device) => ({
        id: device.id,
        name: device.name,
      }));
    })
    .catch(() => undefined);
  unregister = registerCacheEntry({ kind: 'operations', refetch: () => void load() });
});

onBeforeUnmount(() => {
  unregister?.();
});
</script>

<template>
  <div class="operations-list" data-testid="operations-list">
    <div class="operations-list__toolbar">
      <el-select
        v-model="stateFilter"
        placeholder="状态"
        clearable
        class="operations-list__filter"
        data-testid="filter-state"
        @change="applyFilters"
      >
        <el-option
          v-for="operationState in OPERATION_STATES"
          :key="operationState"
          :value="operationState"
          :label="label(OPERATION_STATE_LABELS, operationState)"
        />
      </el-select>
      <el-select
        v-model="deviceFilter"
        placeholder="设备"
        clearable
        filterable
        class="operations-list__filter"
        data-testid="filter-device"
        @change="applyFilters"
      >
        <el-option
          v-for="device in deviceOptions"
          :key="device.id"
          :value="device.id"
          :label="device.name"
        />
      </el-select>
      <el-select
        v-model="requirementFilter"
        placeholder="需求编号"
        clearable
        filterable
        class="operations-list__filter"
        data-testid="filter-requirement"
        @change="applyFilters"
      >
        <el-option
          v-for="requirement in requirementOptions()"
          :key="requirement"
          :value="requirement"
          :label="requirement"
        />
      </el-select>
      <el-select
        v-model="capabilityFilter"
        placeholder="能力键"
        clearable
        filterable
        class="operations-list__filter"
        data-testid="filter-capability"
        @change="applyFilters"
      >
        <el-option
          v-for="capability in capabilityOptions()"
          :key="capability"
          :value="capability"
          :label="capability"
        />
      </el-select>
      <el-button data-testid="filter-reset" @click="clearFilters">清除筛选</el-button>
    </div>

    <AsyncState :state="state" :error="error" :empty-text="emptyText()" @retry="load">
      <el-table
        v-if="(response?.items ?? []).length > 0"
        :data="(response?.items ?? []) as OperationTaskView[]"
        row-key="id"
        class="operations-list__table"
        data-testid="operations-table"
        @row-click="openDetail"
      >
        <el-table-column label="动作" min-width="200">
          <template #default="{ row }">
            <div>
              <code>{{ row.requirement_id }}</code>
            </div>
            <div>
              <code>{{ row.capability_key }}</code>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="设备" min-width="150">
          <template #default="{ row }">{{ row.device.name }}</template>
        </el-table-column>
        <el-table-column label="发起人" width="110">
          <template #default="{ row }">{{ row.requested_by.username }}</template>
        </el-table-column>
        <el-table-column label="状态" width="110">
          <template #default="{ row }"><OperationState :state="row.state" /></template>
        </el-table-column>
        <el-table-column label="进度" width="90">
          <template #default="{ row }">{{ row.progress_percent }}%</template>
        </el-table-column>
        <el-table-column label="开始时间" width="150">
          <template #default="{ row }">{{ formatDateTime(row.started_at) }}</template>
        </el-table-column>
        <el-table-column label="结果摘要" min-width="200">
          <template #default="{ row }">{{ row.result_summary ?? '—' }}</template>
        </el-table-column>
      </el-table>
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
.operations-list__toolbar {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 12px;
}
.operations-list__filter {
  width: 180px;
}
.operations-list__table {
  width: 100%;
  cursor: pointer;
}
</style>
