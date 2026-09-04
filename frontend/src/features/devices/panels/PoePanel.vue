<script setup lang="ts">
import { ElOption, ElSelect } from 'element-plus';
import { computed, onMounted, ref, watch } from 'vue';

import AsyncState from '@/components/AsyncState.vue';
import PaginationBar from '@/components/PaginationBar.vue';
import PortTable from '@/components/PortTable.vue';
import type { ApiError } from '@/api/client';
import { request } from '@/api/client';
import type {
  CapabilityView,
  DeviceComponentsListResponse,
  LatestComponentGroup,
  LatestMetricItem,
} from '@/api/types';
import { METRIC_KEYS } from '@/api/generated/contracts';
import { ENUM_VALUE_LABELS, FRESHNESS_LABELS, METRIC_KEY_LABELS, label } from '@/lib/labels';
import { formatMetricValue, unitLabel } from '@/lib/format';
import { fetchAllLatestGroups, listQueryString } from './common';

// PoE 视图（M5T5，PRODUCT_DESIGN §5.5 PoE 页签 + ACCESS-MON-03）：
// - 设备级摘要：总功耗、功率预算、总功率占比与总功率告警状态（只取
//   设备自身告警状态，ADR-016/025——占比缺分母/告警缺失时如实不显示）；
// - 逐端口行：PoE 端口组件表（供电状态 + 单端口功耗最新指标 chips），
//   服务端分页与状态过滤。
const props = defineProps<{
  deviceId: string;
  requirementIds: string[];
  kinds?: string[];
  capabilities: CapabilityView[];
}>();

const state = ref<'loading' | 'ready' | 'empty' | 'error' | 'permission_denied'>('loading');
const error = ref<ApiError | null>(null);
const response = ref<DeviceComponentsListResponse | null>(null);
const deviceGroup = ref<LatestComponentGroup | null>(null);
const latestByComponent = ref<Record<string, LatestComponentGroup>>({});
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

// 设备级摘要键（device-scope；顺序 = 摘要卡片顺序）。键来自契约注册表，
// 摘要卡片只渲染真正观测到的值，缺失时显示“尚无观测”而不是伪造数字。
const SUMMARY_KEYS = [
  'poe.total_power_w',
  'poe.power_budget_w',
  'poe.total_power_percent',
  'poe.total_power_alarm',
] as const;

const ALARM_TONE: Record<string, string> = {
  normal: 'poe-panel__card-value--success',
  ok: 'poe-panel__card-value--success',
  warning: 'poe-panel__card-value--warning',
  critical: 'poe-panel__card-value--danger',
};

function summaryItem(key: string): LatestMetricItem | undefined {
  return deviceGroup.value?.metrics.find((item) => item.metric_key === key);
}

function hasSummaryObservation(): boolean {
  return SUMMARY_KEYS.some((key) => summaryItem(key) !== undefined);
}

function summaryValue(key: string): string {
  const item = summaryItem(key);
  if (item === undefined || item.value === null || item.value === undefined) {
    return '尚无观测';
  }
  const raw = item.value;
  if (typeof raw === 'boolean') {
    return raw ? '是' : '否';
  }
  if (typeof raw === 'string') {
    return label(ENUM_VALUE_LABELS, raw);
  }
  return formatMetricValue(raw);
}

function summaryToneClass(key: string): string {
  if (key !== 'poe.total_power_alarm') {
    return '';
  }
  const item = summaryItem(key);
  if (item === undefined || typeof item.value !== 'string') {
    return '';
  }
  return ALARM_TONE[item.value] ?? '';
}

function summaryUnit(key: string): string {
  const item = summaryItem(key);
  if (item === undefined || typeof item.value !== 'number') {
    return '';
  }
  return unitLabel(item.unit);
}

function summaryFreshness(key: string): string | undefined {
  return summaryItem(key)?.freshness;
}

function summaryTitle(key: string): string {
  const freshness = summaryFreshness(key);
  if (freshness === undefined) {
    return '尚无成功观测';
  }
  return `新鲜度：${label(FRESHNESS_LABELS, freshness)}`;
}

const unsupportedRows = computed(() => {
  const rows: CapabilityView[] = [];
  for (const capability of props.capabilities) {
    if (!props.requirementIds.includes(capability.requirement_id)) {
      continue;
    }
    if (!(METRIC_KEYS as readonly string[]).includes(capability.capability_key)) {
      continue;
    }
    if (capability.support_state !== 'supported') {
      rows.push(capability);
    }
  }
  return rows;
});

function capabilityNote(capability: CapabilityView): string {
  const prefix = capability.support_state === 'not_configured' ? '未配置' : '设备不支持';
  const reason = capability.detail === null || capability.detail === '' ? '' : `：${capability.detail}`;
  return `${prefix}${reason}`;
}

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
          kind: fixedKind,
          status: statusFilter.value,
        })}`,
      ),
      fetchAllLatestGroups(props.deviceId),
    ]);
    response.value = componentsResult;
    deviceGroup.value = latest.device;
    latestByComponent.value = latest.byComponent;
    state.value = componentsResult.total === 0 ? 'empty' : 'ready';
  } catch (caught) {
    error.value = caught as ApiError;
    state.value = error.value.code === 'permission_denied' ? 'permission_denied' : 'error';
  }
}

function emptyText(): string {
  if (statusFilter.value !== null) {
    return '筛选无结果';
  }
  return '尚无 PoE 端口观测数据';
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

watch(
  () => props.kinds,
  () => {
    statusFilter.value = null;
    page.value = 1;
    void load();
  },
);

onMounted(() => {
  void load();
});
</script>

<template>
  <div class="poe-panel" data-testid="poe-panel">
    <AsyncState :state="state" :error="error" :empty-text="emptyText()" @retry="load">
      <p v-if="unsupportedRows.length > 0" class="poe-panel__capability">
        能力状态（该页签承载的指标）：
        <template v-for="capability in unsupportedRows" :key="capability.capability_key">
          <span class="poe-panel__capability-row">
            {{ capability.capability_key }} — {{ capabilityNote(capability) }}
          </span>
        </template>
      </p>

      <section class="poe-panel__summary" data-testid="poe-summary">
        <h3 class="poe-panel__section-title">设备 PoE 总功耗</h3>
        <div v-if="hasSummaryObservation()" class="poe-panel__cards">
          <div
            v-for="key in SUMMARY_KEYS"
            :key="key"
            class="poe-panel__card"
            :data-testid="`poe-summary-${key}`"
          >
            <span class="poe-panel__card-label">{{
              label(METRIC_KEY_LABELS, key)
            }}</span>
            <span
              class="poe-panel__card-value"
              :class="summaryToneClass(key)"
              :title="summaryTitle(key)"
            >
              {{ summaryValue(key) }}
              <span v-if="summaryUnit(key)" class="poe-panel__card-unit">{{
                summaryUnit(key)
              }}</span>
            </span>
          </div>
        </div>
        <p v-else class="poe-panel__none" data-testid="poe-summary-none">
          尚无设备级 PoE 观测（总功耗/预算/占比/告警只显示设备实际报告的值，不伪造百分比或 normal 状态）
        </p>
      </section>

      <section class="poe-panel__ports">
        <h3 class="poe-panel__section-title">PoE 端口供电</h3>
        <div class="poe-panel__toolbar">
          <el-select
            v-model="statusFilter"
            placeholder="状态"
            clearable
            class="poe-panel__filter"
            data-testid="filter-poe-status"
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
        <p v-else-if="state === 'ready'" class="poe-panel__none">
          尚无 PoE 端口组件行
        </p>
        <PaginationBar
          v-model:page="page"
          v-model:page-size="pageSize"
          :total="response?.total ?? 0"
          @update:page="onPageChange"
          @update:page-size="onPageSizeChange"
        />
      </section>
    </AsyncState>
  </div>
</template>

<style scoped>
.poe-panel__toolbar {
  display: flex;
  gap: 8px;
  margin-bottom: 12px;
}
.poe-panel__filter {
  width: 180px;
}
.poe-panel__capability {
  color: var(--warden-status-warning);
  font-size: 12px;
  margin: 0 0 8px;
}
.poe-panel__capability-row {
  display: block;
  padding: 2px 0;
}
.poe-panel__section-title {
  margin: 0 0 8px;
  font-size: 14px;
}
.poe-panel__summary {
  margin-bottom: 18px;
}
.poe-panel__cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 10px;
}
.poe-panel__card {
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 4px;
  padding: 10px 12px;
}
.poe-panel__card-label {
  display: block;
  color: var(--warden-status-unknown);
  font-size: 12px;
  margin-bottom: 6px;
}
.poe-panel__card-value {
  font-family: monospace;
  font-size: 18px;
  font-weight: 600;
}
.poe-panel__card-value--success {
  color: var(--warden-status-healthy);
}
.poe-panel__card-value--warning {
  color: var(--warden-status-warning);
}
.poe-panel__card-value--danger {
  color: var(--warden-status-critical);
}
.poe-panel__card-unit {
  color: var(--warden-status-unknown);
  font-size: 13px;
  margin-left: 2px;
}
.poe-panel__none {
  color: var(--warden-status-unknown);
  font-size: 13px;
  margin: 4px 0;
}
</style>
