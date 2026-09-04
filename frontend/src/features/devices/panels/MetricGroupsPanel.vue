<script setup lang="ts">
import { ElButton } from 'element-plus';
import { computed, onMounted, ref } from 'vue';

import AsyncState from '@/components/AsyncState.vue';
import MetricChart from '@/components/MetricChart.vue';
import MetricValue from '@/components/MetricValue.vue';
import type { ApiError } from '@/api/client';
import { request } from '@/api/client';
import type {
  CapabilityView,
  DeviceMetricsLatestResponse,
  LatestComponentGroup,
  LatestMetricItem,
} from '@/api/types';
import { METRIC_KEYS, METRIC_META, REQUIREMENTS } from '@/api/generated/contracts';
import { METRIC_KEY_LABELS, label } from '@/lib/labels';
import { listQueryString } from './common';

// 按 MON 需求分组展示最新指标（UI_SPEC §7.2/§7.3）：
// - 支持状态来自能力发现；unsupported/not_configured 显示原因，不与
//   "尚无观测"（freshness unknown）共用文案；
// - 数值指标支持展开趋势图（MetricChart，缺口留空、最多 8 条、单位来自契约）。
const props = defineProps<{
  deviceId: string;
  requirementIds: string[];
  capabilities: CapabilityView[];
}>();

const state = ref<'loading' | 'ready' | 'error' | 'permission_denied'>('loading');
const error = ref<ApiError | null>(null);
const latest = ref<DeviceMetricsLatestResponse | null>(null);
const expandedCharts = ref<Set<string>>(new Set());

const PAGE_SIZE = 100;

async function load(): Promise<void> {
  state.value = 'loading';
  error.value = null;
  try {
    latest.value = await request<DeviceMetricsLatestResponse>(
      `/devices/${props.deviceId}/metrics/latest?${listQueryString({ page: 1, page_size: PAGE_SIZE })}`,
    );
    state.value = 'ready';
  } catch (caught) {
    error.value = caught as ApiError;
    state.value = error.value.code === 'permission_denied' ? 'permission_denied' : 'error';
  }
}

onMounted(() => {
  // M6T1：挂载即加载（此前只绑定了重试按钮，页面永远停留在骨架屏）
  void load();
});

const requirementGroups = computed(() => {
  return props.requirementIds
    .map((requirementId) => {
      const rows = props.capabilities.filter(
        (capability) => capability.requirement_id === requirementId,
      );
      const metricRows = rows.filter((row) =>
        (METRIC_KEYS as readonly string[]).includes(row.capability_key),
      );
      const eventRows = rows.filter(
        (row) => !(METRIC_KEYS as readonly string[]).includes(row.capability_key),
      );
      return { requirementId, rows, metricRows, eventRows };
    })
    .filter((group) => group.rows.length > 0 || group.metricRows.length > 0);
});

function keyObserved(
  key: string,
): { component: NonNullable<LatestComponentGroup['component']> | null; item: LatestMetricItem }[] {
  const result: {
    component: NonNullable<LatestComponentGroup['component']> | null;
    item: LatestMetricItem;
  }[] = [];
  for (const group of groupsWithKey(key)) {
    for (const item of group.metrics) {
      if (item.metric_key === key) {
        result.push({ component: group.component ?? null, item });
      }
    }
  }
  return result;
}

function groupsWithKey(key: string): LatestComponentGroup[] {
  const groups = latest.value?.items ?? [];
  return groups.filter((group) => group.metrics.some((item) => item.metric_key === key));
}

function numericGaugeRows(group: { metricRows: CapabilityView[] }) {
  return group.metricRows.filter((row) => {
    const meta = METRIC_META[row.capability_key];
    return (
      meta !== undefined &&
      meta.series === 'gauge' &&
      (meta.valueType === 'number' || meta.valueType === 'integer')
    );
  });
}

function isUnsupported(row: CapabilityView): boolean {
  return row.support_state === 'unsupported' || row.support_state === 'not_configured';
}

function unsupportedText(row: CapabilityView): string {
  if (row.support_state === 'not_configured') {
    return `未配置：${row.detail ?? '缺少必要配置'}`;
  }
  return `设备不支持：${row.detail ?? '无附加原因'}`;
}

function toggleChart(key: string): void {
  const next = new Set(expandedCharts.value);
  if (next.has(key)) {
    next.delete(key);
  } else {
    next.add(key);
  }
  expandedCharts.value = next;
}

function chartCandidates(key: string) {
  return groupsWithKey(key)
    .map((group) => group.component)
    .filter((component): component is NonNullable<typeof component> => component !== null);
}
</script>

<template>
  <AsyncState :state="state" :error="error" empty-text="暂无指标数据" @retry="load">
    <div
      v-if="latest && requirementGroups.length > 0"
      class="metric-groups"
      data-testid="metric-groups"
    >
      <p v-if="(latest.items ?? []).length > 0 && latest.total > latest.items.length" class="metric-groups__truncated">
        共 {{ latest.total }} 个组件组，仅展示前 {{ latest.items.length }} 组
      </p>
      <section
        v-for="group in requirementGroups"
        :key="group.requirementId"
        class="metric-groups__group"
        :data-testid="`metric-group-${group.requirementId}`"
      >
        <h3 class="metric-groups__title">
          <span class="metric-groups__requirement">{{ group.requirementId }}</span>
          {{ REQUIREMENTS[group.requirementId]?.title ?? '' }}
        </h3>

        <p v-if="group.metricRows.length === 0" class="metric-groups__note">
          该需求没有指标展示；事件类内容见「事件」页签
          <template v-if="group.eventRows.length > 0">
            （{{ group.eventRows.map((row) => row.capability_key).join('、') }}）
          </template>
        </p>

        <table
          v-if="group.metricRows.length > 0"
          class="metric-groups__table"
          :data-testid="`metric-table-${group.requirementId}`"
        >
          <thead>
            <tr>
              <th>指标</th>
              <th>组件</th>
              <th>当前值</th>
            </tr>
          </thead>
          <tbody>
            <template v-for="row in group.metricRows" :key="row.capability_key">
              <tr v-if="isUnsupported(row)" class="metric-groups__row-unsupported">
                <td>{{ label(METRIC_KEY_LABELS, row.capability_key) }}</td>
                <td colspan="2" class="metric-groups__unsupported">
                  {{ row.capability_key }} — {{ unsupportedText(row) }}
                </td>
              </tr>
              <template v-else>
                <template v-if="keyObserved(row.capability_key).length > 0">
                  <tr
                    v-for="observed in keyObserved(row.capability_key)"
                    :key="`${row.capability_key}-${observed.item.observed_at}-${observed.component?.id ?? 'device'}`"
                  >
                    <td>{{ label(METRIC_KEY_LABELS, row.capability_key) }}</td>
                    <td>
                      <span v-if="observed.component">
                        {{ observed.component.native_id }}（{{
                          observed.component.name || observed.component.kind
                        }}）
                      </span>
                      <span v-else>设备级</span>
                    </td>
                    <td><MetricValue :item="observed.item" /></td>
                  </tr>
                </template>
                <tr v-else class="metric-groups__row-unknown">
                  <td>{{ label(METRIC_KEY_LABELS, row.capability_key) }}</td>
                  <td colspan="2">
                    {{ row.capability_key }} — 尚无观测数据（受支持指标尚未产生一次成功观测）
                  </td>
                </tr>
              </template>
            </template>
          </tbody>
        </table>

        <div v-if="group.metricRows.length > 0" class="metric-groups__charts">
          <div v-for="row in numericGaugeRows(group)" :key="`chart-${row.capability_key}`">
            <el-button size="small" plain @click="toggleChart(row.capability_key)">
              {{ expandedCharts.has(row.capability_key) ? '收起趋势' : '查看趋势' }}
              （{{ label(METRIC_KEY_LABELS, row.capability_key) }}）
            </el-button>
            <MetricChart
              v-if="expandedCharts.has(row.capability_key)"
              :device-id="deviceId"
              :metric-key="row.capability_key"
              :candidate-components="chartCandidates(row.capability_key)"
            />
          </div>
        </div>
      </section>
    </div>
    <p v-else-if="latest && requirementGroups.length === 0" class="metric-groups__note">
      该设备尚无对应的能力发现记录
    </p>
  </AsyncState>
</template>

<style scoped>
.metric-groups__truncated {
  color: var(--warden-status-unknown);
  font-size: 12px;
}
.metric-groups__group {
  margin-bottom: 22px;
}
.metric-groups__title {
  margin: 0 0 8px;
  font-size: 15px;
}
.metric-groups__requirement {
  font-family: monospace;
  color: var(--warden-status-unknown);
  margin-right: 10px;
  font-size: 12px;
}
.metric-groups__note {
  color: var(--warden-status-unknown);
  font-size: 13px;
  margin: 4px 0;
}
.metric-groups__table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
.metric-groups__table th,
.metric-groups__table td {
  text-align: left;
  padding: 6px 10px;
  border-bottom: 1px solid var(--el-border-color-lighter);
  vertical-align: top;
}
.metric-groups__table th {
  color: var(--warden-status-unknown);
  font-weight: 500;
  width: 160px;
}
.metric-groups__unsupported {
  color: var(--warden-status-warning);
}
.metric-groups__charts {
  margin-top: 10px;
  display: flex;
  flex-direction: column;
  gap: 10px;
  align-items: flex-start;
}
</style>
