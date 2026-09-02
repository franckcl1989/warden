<script setup lang="ts">
import { ElButton, ElInput, ElOption, ElSelect, ElTable, ElTableColumn } from 'element-plus';
import { onMounted, reactive, ref } from 'vue';
import { useRouter } from 'vue-router';

import AsyncState from '@/components/AsyncState.vue';
import PaginationBar from '@/components/PaginationBar.vue';
import ReachabilityBadge from '@/components/ReachabilityBadge.vue';
import HealthBadge from '@/components/HealthBadge.vue';
import type { ApiError } from '@/api/client';
import { request } from '@/api/client';
import type { DeviceListResponse, DeviceView } from '@/api/types';
import { DEVICE_TYPES } from '@/api/generated/contracts';
import { DEVICE_TYPE_LABELS, HEALTH_LABELS, REACHABILITY_LABELS, label } from '@/lib/labels';
import { formatDateTime } from '@/lib/format';
import { useAuthStore } from '@/stores/auth';

// 设备列表（PLT-02，PRODUCT_DESIGN §4.1）。筛选与排序全部由服务端完成。
const auth = useAuthStore();
const router = useRouter();

const state = ref<'loading' | 'ready' | 'empty' | 'error' | 'permission_denied'>('loading');
const error = ref<ApiError | null>(null);
const list = ref<DeviceListResponse | null>(null);
const page = ref(1);
const pageSize = ref(20);
const sort = ref('name');
const sortOrder = ref<'ascending' | 'descending' | null>(null);

const filters = reactive<{
  name: string;
  deviceType: string | null;
  vendor: string;
  health: string | null;
  reachability: string | null;
  enabled: boolean | null;
}>({
  name: '',
  deviceType: null,
  vendor: '',
  health: null,
  reachability: null,
  enabled: null,
});

const filterTouched = ref(false);

function queryString(): string {
  const params = new URLSearchParams({
    page: String(page.value),
    page_size: String(pageSize.value),
  });
  if (sortOrder.value === 'ascending') params.set('sort', sort.value);
  if (sortOrder.value === 'descending') params.set('sort', `-${sort.value}`);
  if (filters.name) params.set('name', filters.name);
  if (filters.deviceType) params.set('device_type', filters.deviceType);
  if (filters.vendor) params.set('vendor', filters.vendor);
  if (filters.health) params.set('health', filters.health);
  if (filters.reachability) params.set('reachability', filters.reachability);
  if (filters.enabled !== null) params.set('enabled', String(filters.enabled));
  return params.toString();
}

async function load(): Promise<void> {
  state.value = 'loading';
  error.value = null;
  try {
    list.value = await request<DeviceListResponse>(`/devices?${queryString()}`);
    state.value = list.value.total === 0 ? 'empty' : 'ready';
  } catch (caught) {
    error.value = caught as ApiError;
    state.value = error.value.code === 'permission_denied' ? 'permission_denied' : 'error';
  }
}

function applyFilters(): void {
  filterTouched.value = true;
  page.value = 1;
  void load();
}

function clearFilters(): void {
  filters.name = '';
  filters.deviceType = null;
  filters.vendor = '';
  filters.health = null;
  filters.reachability = null;
  filters.enabled = null;
  filterTouched.value = false;
  page.value = 1;
  void load();
}

function onSortChange({
  prop,
  order,
}: {
  prop: string | null;
  order: 'ascending' | 'descending' | null;
}): void {
  if (prop === null) return;
  sort.value = prop;
  sortOrder.value = order;
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

function openDetail(row: DeviceView): void {
  void router.push({ name: 'device-detail', params: { id: row.id } });
}

function emptyText(): string {
  if (list.value === null) return '暂无数据';
  if (
    filterTouched.value ||
    Object.values(filters).some((value) => value !== '' && value !== null)
  ) {
    return '筛选无结果';
  }
  return '尚未添加设备';
}

function onEmptyAction(): void {
  if (emptyText() === '筛选无结果') {
    clearFilters();
  } else {
    void load();
  }
}

onMounted(() => {
  void load();
});
</script>

<template>
  <div class="devices-list">
    <div class="devices-list__toolbar">
      <el-input
        v-model="filters.name"
        placeholder="按名称筛选"
        clearable
        class="devices-list__filter devices-list__filter--name"
        data-testid="filter-name"
        @keyup.enter="applyFilters"
        @clear="applyFilters"
      />
      <el-select
        v-model="filters.deviceType"
        placeholder="设备类别"
        clearable
        class="devices-list__filter"
        data-testid="filter-type"
        @change="applyFilters"
      >
        <el-option
          v-for="type in DEVICE_TYPES"
          :key="type"
          :value="type"
          :label="label(DEVICE_TYPE_LABELS, type)"
        />
      </el-select>
      <el-input
        v-model="filters.vendor"
        placeholder="按厂商筛选"
        clearable
        class="devices-list__filter"
        @keyup.enter="applyFilters"
        @clear="applyFilters"
      />
      <el-select
        v-model="filters.reachability"
        placeholder="可达性"
        clearable
        class="devices-list__filter"
        @change="applyFilters"
      >
        <el-option
          v-for="item in ['unknown', 'online', 'offline']"
          :key="item"
          :value="item"
          :label="label(REACHABILITY_LABELS, item)"
        />
      </el-select>
      <el-select
        v-model="filters.health"
        placeholder="健康"
        clearable
        class="devices-list__filter"
        @change="applyFilters"
      >
        <el-option
          v-for="item in ['unknown', 'healthy', 'warning', 'critical']"
          :key="item"
          :value="item"
          :label="label(HEALTH_LABELS, item)"
        />
      </el-select>
      <el-select
        v-model="filters.enabled"
        placeholder="启用状态"
        clearable
        class="devices-list__filter"
        data-testid="filter-enabled"
        @change="applyFilters"
      >
        <el-option :value="true" label="已启用" />
        <el-option :value="false" label="已停用" />
      </el-select>
      <el-button data-testid="filter-reset" @click="clearFilters">清除筛选</el-button>
      <el-button
        v-if="auth.isAdmin"
        type="primary"
        class="devices-list__add"
        data-testid="add-device"
        @click="router.push({ name: 'devices-new' })"
      >
        添加设备
      </el-button>
    </div>

    <AsyncState
      :state="state"
      :error="error"
      :empty-text="emptyText()"
      :empty-action="emptyText() === '筛选无结果' ? '清除筛选' : undefined"
      @retry="onEmptyAction"
    >
      <el-table
        :data="list?.items ?? []"
        class="devices-list__table"
        row-key="id"
        @row-click="openDetail"
        @sort-change="onSortChange"
      >
        <el-table-column prop="name" label="名称" min-width="160" sortable="custom" />
        <el-table-column prop="device_type" label="类别" width="120" sortable="custom">
          <template #default="{ row }">{{ label(DEVICE_TYPE_LABELS, row.device_type) }}</template>
        </el-table-column>
        <el-table-column label="厂商/型号" min-width="160">
          <template #default="{ row }">
            <span v-if="row.vendor || row.model"
              >{{ row.vendor ?? '—' }} {{ row.model ?? '' }}</span
            >
            <span v-else>—</span>
          </template>
        </el-table-column>
        <el-table-column prop="management_endpoint" label="管理地址" min-width="140" />
        <el-table-column label="可达性" width="90">
          <template #default="{ row }">
            <ReachabilityBadge :reachability="row.reachability" />
          </template>
        </el-table-column>
        <el-table-column label="健康" width="130">
          <template #default="{ row }">
            <HealthBadge :health="row.health" :last-known-health="row.last_known_health" />
          </template>
        </el-table-column>
        <el-table-column label="当前问题数" width="100">
          <!-- 当前问题数由 M2 告警模块提供；0.1.0 占位 0（PRODUCT_DESIGN §4.1 字段保留） -->
          <template #default>0</template>
        </el-table-column>
        <el-table-column label="最近采集时间" width="140">
          <!-- 0.1.0 无采集流水线；字段保留，展示 API 返回值，无值显示 — -->
          <template #default="{ row }">{{ formatDateTime(row.last_collected_at) }}</template>
        </el-table-column>
        <el-table-column label="启用状态" width="90" fixed="right">
          <template #default="{ row }">{{ row.enabled ? '已启用' : '已停用' }}</template>
        </el-table-column>
      </el-table>
      <PaginationBar
        v-model:page="page"
        v-model:page-size="pageSize"
        :total="list?.total ?? 0"
        @update:page="onPageChange"
        @update:page-size="onPageSizeChange"
      />
    </AsyncState>
  </div>
</template>

<style scoped>
.devices-list__toolbar {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 12px;
}
.devices-list__filter {
  width: 160px;
}
.devices-list__filter--name {
  width: 200px;
}
.devices-list__add {
  margin-left: auto;
}
.devices-list__table {
  width: 100%;
  cursor: pointer;
}
</style>
