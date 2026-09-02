<script setup lang="ts">
import { ElOption, ElSelect, ElTable, ElTableColumn, ElTag } from 'element-plus';
import { onMounted, ref } from 'vue';

import AsyncState from '@/components/AsyncState.vue';
import PaginationBar from '@/components/PaginationBar.vue';
import type { ApiError } from '@/api/client';
import { request } from '@/api/client';
import type { CollectionRunView, DeviceCollectionRunsListResponse } from '@/api/types';
import { formatDateTime } from '@/lib/format';
import { COLLECTION_STATE_LABELS, COLLECTION_TYPE_LABELS, label } from '@/lib/labels';
import { listQueryString } from './common';

// 采集历史页签（PLT-03）：按采集类型/状态过滤，展示错误码与摘要。
const props = defineProps<{
  deviceId: string;
}>();

const COLLECTION_TYPES = ['metrics', 'logs', 'discovery'];
const COLLECTION_STATES = ['scheduled', 'running', 'succeeded', 'partial', 'failed'];

const state = ref<'loading' | 'ready' | 'empty' | 'error' | 'permission_denied'>('loading');
const error = ref<ApiError | null>(null);
const response = ref<DeviceCollectionRunsListResponse | null>(null);
const typeFilter = ref<string | null>(null);
const stateFilter = ref<string | null>(null);
const page = ref(1);
const pageSize = ref(20);

async function load(): Promise<void> {
  state.value = 'loading';
  error.value = null;
  try {
    const query = listQueryString({
      page: page.value,
      page_size: pageSize.value,
      collection_type: typeFilter.value,
      state: stateFilter.value,
    });
    const result = await request<DeviceCollectionRunsListResponse>(
      `/devices/${props.deviceId}/collection-runs?${query}`,
    );
    response.value = result;
    state.value = result.total === 0 ? 'empty' : 'ready';
  } catch (caught) {
    error.value = caught as ApiError;
    state.value = error.value.code === 'permission_denied' ? 'permission_denied' : 'error';
  }
}

function applyFilters(): void {
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

function stateTagType(run: { state: string }): 'success' | 'warning' | 'danger' | 'primary' {
  switch (run.state) {
    case 'succeeded':
      return 'success';
    case 'failed':
      return 'danger';
    case 'partial':
      return 'warning';
    case 'running':
    case 'scheduled':
      return 'primary';
    default:
      return 'primary';
  }
}

onMounted(() => {
  void load();
});
</script>

<template>
  <div class="collection-runs">
    <div class="collection-runs__toolbar">
      <el-select
        v-model="typeFilter"
        placeholder="采集类型"
        clearable
        class="collection-runs__filter"
        data-testid="filter-run-type"
        @change="applyFilters"
      >
        <el-option
          v-for="type in COLLECTION_TYPES"
          :key="type"
          :value="type"
          :label="label(COLLECTION_TYPE_LABELS, type)"
        />
      </el-select>
      <el-select
        v-model="stateFilter"
        placeholder="状态"
        clearable
        class="collection-runs__filter"
        data-testid="filter-run-state"
        @change="applyFilters"
      >
        <el-option
          v-for="runState in COLLECTION_STATES"
          :key="runState"
          :value="runState"
          :label="label(COLLECTION_STATE_LABELS, runState)"
        />
      </el-select>
    </div>

    <AsyncState :state="state" :error="error" :empty-text="'尚无采集记录'" @retry="load">
      <el-table
        v-if="(response?.items ?? []).length > 0"
        :data="(response?.items ?? []) as CollectionRunView[]"
        row-key="id"
        data-testid="collection-runs-table"
      >
        <el-table-column label="采集类型" width="130">
          <template #default="{ row }">{{
            label(COLLECTION_TYPE_LABELS, row.collection_type)
          }}</template>
        </el-table-column>
        <el-table-column label="状态" width="110">
          <template #default="{ row }">
            <el-tag :type="stateTagType(row as CollectionRunView)" size="small">
              {{ label(COLLECTION_STATE_LABELS, row.state) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="计划时间" width="150">
          <template #default="{ row }">{{ formatDateTime(row.scheduled_at) }}</template>
        </el-table-column>
        <el-table-column label="开始时间" width="150">
          <template #default="{ row }">{{ formatDateTime(row.started_at) }}</template>
        </el-table-column>
        <el-table-column label="尝试/成功/失败" width="130">
          <template #default="{ row }">
            {{ row.attempt_count }} / {{ row.success_count }} / {{ row.failure_count }}
          </template>
        </el-table-column>
        <el-table-column label="错误" min-width="220">
          <template #default="{ row }">
            <span v-if="row.error_code" class="collection-runs__error">
              {{ row.error_code }}
              <span v-if="row.error_summary">：{{ row.error_summary }}</span>
            </span>
            <span v-else>—</span>
          </template>
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
.collection-runs__toolbar {
  display: flex;
  gap: 8px;
  margin-bottom: 12px;
}
.collection-runs__filter {
  width: 180px;
}
.collection-runs__error {
  color: var(--warden-status-critical);
  font-family: monospace;
  font-size: 12px;
}
</style>
