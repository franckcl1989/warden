<script setup lang="ts">
import { ElOption, ElSelect } from 'element-plus';
import { onMounted, ref, watch } from 'vue';

import AsyncState from '@/components/AsyncState.vue';
import PaginationBar from '@/components/PaginationBar.vue';
import PortTable from '@/components/PortTable.vue';
import type { ApiError } from '@/api/client';
import { request } from '@/api/client';
import type {
  CapabilityView,
  DeviceComponentsListResponse,
  LatestComponentGroup,
} from '@/api/types';
import { METRIC_KEYS } from '@/api/generated/contracts';
import { ENUM_VALUE_LABELS, label } from '@/lib/labels';
import { fetchAllLatestGroups, listQueryString } from './common';

// 端口/部件表视图（M5T5，PRODUCT_DESIGN §5.4-5.5 端口/光模块/PoE 端口行）：
// 服务端分页（/components，kind/status 过滤）的行列表，每行展示该组件最新
// 指标 chips（/metrics/latest 按组件分组，一次取全后按组件 id 关联——取不到的
// 行如实显示“尚无观测”，绝不伪造值）。组件自身支持状态来自能力发现；
// unsupported/not_configured 的能力键与通用“暂无数据”区分显示。
const props = defineProps<{
  deviceId: string;
  requirementIds: string[];
  kinds?: string[];
  capabilities: CapabilityView[];
}>();

const state = ref<'loading' | 'ready' | 'empty' | 'error' | 'permission_denied'>('loading');
const error = ref<ApiError | null>(null);
const response = ref<DeviceComponentsListResponse | null>(null);
const latestByComponent = ref<Record<string, LatestComponentGroup>>({});
const kindFilter = ref<string | null>(null);
const statusFilter = ref<string | null>(null);
const page = ref(1);
const pageSize = ref(20);

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

/** 该分区承载的能力行中“非支持”的指标键（unsupported/not_configured）。 */
const unsupportedRows = (): CapabilityView[] => {
  const rows: CapabilityView[] = [];
  for (const capability of props.capabilities) {
    if (!props.requirementIds.includes(capability.requirement_id)) {
      continue;
    }
    if (!(METRIC_KEYS as readonly string[]).includes(capability.capability_key)) {
      continue;
    }
    if (capability.support_state === 'supported') {
      continue;
    }
    rows.push(capability);
  }
  return rows;
};

async function load(): Promise<void> {
  state.value = 'loading';
  error.value = null;
  try {
    const fixedKind = props.kinds?.[0] ?? null;
    const [componentsResult, latest] = await Promise.all([
      request<DeviceComponentsListResponse>(
        `/devices/${props.deviceId}/components?${listQueryString({
          page: page.value,
          page_size: pageSize.value,
          kind: kindFilter.value ?? fixedKind,
          status: statusFilter.value,
        })}`,
      ),
      fetchAllLatestGroups(props.deviceId),
    ]);
    response.value = componentsResult;
    latestByComponent.value = latest.byComponent;
    state.value = componentsResult.total === 0 ? 'empty' : 'ready';
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

function onStatusChange(): void {
  page.value = 1;
  void load();
}

function onKindChange(): void {
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
    return [...(props.kinds ?? [])];
  }
  return options;
}

function multiKind(): boolean {
  return (props.kinds?.length ?? 0) > 1;
}

function capabilityNote(capability: CapabilityView): string {
  const prefix =
    capability.support_state === 'not_configured' ? '未配置' : '设备不支持';
  const reason = capability.detail === null || capability.detail === '' ? '' : `：${capability.detail}`;
  return `${prefix}${reason}`;
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
  <div class="ports-panel" data-testid="ports-panel">
    <AsyncState :state="state" :error="error" :empty-text="emptyText()" @retry="load">
      <p v-if="unsupportedRows().length > 0" class="ports-panel__capability">
        能力状态（该页签承载的指标）：
        <template v-for="capability in unsupportedRows()" :key="capability.capability_key">
          <span class="ports-panel__capability-row">
            {{ capability.capability_key }} — {{ capabilityNote(capability) }}
          </span>
        </template>
      </p>

      <div class="ports-panel__toolbar">
        <el-select
          v-if="multiKind()"
          v-model="kindFilter"
          placeholder="组件类型"
          clearable
          class="ports-panel__filter"
          data-testid="filter-port-kind"
          @change="onKindChange"
        >
          <el-option v-for="kind in selectKindOptions()" :key="kind" :value="kind" :label="kind" />
        </el-select>
        <el-select
          v-model="statusFilter"
          placeholder="状态"
          clearable
          class="ports-panel__filter"
          data-testid="filter-port-status"
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

      <PortTable
        v-if="(response?.items ?? []).length > 0"
        :items="response?.items ?? []"
        :latest-by-component="latestByComponent"
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
.ports-panel__toolbar {
  display: flex;
  gap: 8px;
  margin-bottom: 12px;
}
.ports-panel__filter {
  width: 180px;
}
.ports-panel__capability {
  color: var(--warden-status-warning);
  font-size: 12px;
  margin: 0 0 8px;
}
.ports-panel__capability-row {
  display: block;
  padding: 2px 0;
}
</style>
