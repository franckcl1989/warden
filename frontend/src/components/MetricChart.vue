<script setup lang="ts">
import {
  ElButton,
  ElCheckbox,
  ElCheckboxGroup,
  ElRadioButton,
  ElRadioGroup,
  ElSkeleton,
} from 'element-plus';
import * as echarts from 'echarts';
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue';

import type { ApiError } from '@/api/client';
import { request } from '@/api/client';
import type { ComponentRef, DeviceMetricsSeriesResponse } from '@/api/types';
import { METRIC_META, type MetricKey } from '@/api/generated/contracts';
import { ENUM_VALUE_LABELS, label as lookupLabel, RESOLUTION_LABELS } from '@/lib/labels';
import { formatAxisNumber, formatDateTime, formatMetricValue, unitLabel } from '@/lib/format';

/**
 * UI_SPEC §7.3 MetricChart：统一时间轴、单位、空洞和质量提示。
 * - 时间范围 1h/6h/24h/7d/30d/180d，默认 24 小时；
 * - 分辨率由服务端按窗口决定（7 天内 raw、30 天 5m、180 天 1h），
 *   界面显示响应中的实际分辨率；
 * - 数据缺口保持空白（connectNulls=false），禁止用上一值连线；
 * - 不发明 warning/critical 参考线（UI_SPEC §7.3）；
 * - 最多 8 条序列（组件选择器限制）；
 * - 枚举/布尔（state 系列）渲染为阶梯变化点，不做平均；
 * - 单位为 contracts/metrics.json 定义（生成 contracts.ts METRIC_META）；
 * - 图表下方提供当前/最大/最小文本摘要（UI_SPEC §12 无障碍）。
 */

export interface MetricChartPoint {
  timestamp: string;
  value: number | string | boolean | null;
  quality: string;
}

const RANGES: { label: string; hours: number }[] = [
  { label: '1 小时', hours: 1 },
  { label: '6 小时', hours: 6 },
  { label: '24 小时', hours: 24 },
  { label: '7 天', hours: 24 * 7 },
  { label: '30 天', hours: 24 * 30 },
  { label: '180 天', hours: 24 * 180 },
];

const MAX_SERIES = 8;

const props = withDefaults(
  defineProps<{
    deviceId: string;
    metricKey: MetricKey | string;
    /** 承载该指标的组件候选（component 作用域）；device 作用域指标忽略。 */
    candidateComponents?: ComponentRef[];
    /** 外部希望默认选中的组件；数量超过 8 时只取前 8。 */
    defaultSelection?: ComponentRef[];
  }>(),
  { candidateComponents: () => [], defaultSelection: undefined },
);

const state = ref<'loading' | 'ready' | 'error' | 'empty'>('loading');
const error = ref<ApiError | null>(null);
const rangeHours = ref(24);
const resolutionLabel = ref<string>('');
const unitText = ref<string>('');
const stateValues = ref<string[]>([]);
const seriesResponses = ref<DeviceMetricsSeriesResponse[]>([]);

// 请求序列号：范围/序列切换后，较早的慢响应不得覆盖较新的结果
let requestSeq = 0;

const meta = computed(() => METRIC_META[props.metricKey]);
const isStateSeries = computed(() => meta.value?.series === 'state');
const scopeDevice = computed(() => meta.value?.scope === 'device');

const chartContainer = ref<HTMLDivElement | null>(null);
const chartTextSummary = ref<string>('');
const chartPointsText = ref<string>('');
let chart: echarts.ECharts | null = null;
let chartFailed = false;

const selectedIds = ref<string[]>([]);

watch(
  () => [props.deviceId, props.metricKey] as const,
  () => {
    void initSelectionAndLoad();
  },
);

watch(selectedIds, () => {
  void loadSeries();
});

watch(rangeHours, () => {
  void loadSeries();
});

watch(
  () => props.candidateComponents,
  () => {
    if (scopeDevice.value) {
      return;
    }
    if (selectedIds.value.length === 0 && props.candidateComponents.length > 0) {
      initSelectionAndLoad();
    }
  },
);

function componentById(id: string): ComponentRef | undefined {
  return props.candidateComponents.find((component) => component.id === id);
}

function componentCandidates(): ComponentRef[] {
  if (scopeDevice.value) {
    return [];
  }
  return props.candidateComponents;
}

function initSelectionAndLoad(): void {
  let next: ComponentRef[];
  if (props.defaultSelection !== undefined && props.defaultSelection.length > 0) {
    next = props.defaultSelection.slice(0, MAX_SERIES);
  } else {
    const candidates = componentCandidates();
    if (candidates.length <= MAX_SERIES) {
      next = candidates;
    } else {
      // 多组件默认展示前 8 条，用户可自行切换（UI_SPEC §7.3）
      next = candidates.slice(0, MAX_SERIES);
    }
  }
  const nextIds = next.map((component) => component.id);
  const same =
    nextIds.length === selectedIds.value.length &&
    nextIds.every((id, index) => selectedIds.value[index] === id);
  if (same) {
    void loadSeries();
    return;
  }
  selectedIds.value = nextIds;
}

function rangeFrom(): string {
  const end = new Date();
  return new Date(end.getTime() - rangeHours.value * 3600 * 1000).toISOString();
}

function rangeTo(): string {
  return new Date().toISOString();
}

async function loadSeries(): Promise<void> {
  const seq = ++requestSeq;
  state.value = 'loading';
  error.value = null;
  seriesResponses.value = [];
  const requests: Promise<DeviceMetricsSeriesResponse>[] = [];
  const targets = scopeDevice.value ? [undefined] : selectedIds.value;
  for (const componentId of targets) {
    const query = new URLSearchParams({
      metric: props.metricKey,
      from: rangeFrom(),
      to: rangeTo(),
    });
    if (componentId !== undefined) {
      query.set('component_id', componentId);
    }
    requests.push(
      request<DeviceMetricsSeriesResponse>(`/devices/${props.deviceId}/metrics/series?${query}`),
    );
  }
  try {
    const results = await Promise.all(requests);
    if (seq !== requestSeq) {
      return; // 已有更新的请求：丢弃过期响应，避免旧数据覆盖新选择
    }
    seriesResponses.value = results;
    if (results.length === 0 || results.every((result) => result.points.length === 0)) {
      state.value = 'empty';
      return;
    }
    const first = results[0];
    if (first === undefined) {
      state.value = 'empty';
      return;
    }
    resolutionLabel.value = lookupLabel(RESOLUTION_LABELS, first.resolution);
    unitText.value = first.unit ? unitLabel(first.unit) : '';
    const values: string[] = [];
    for (const result of results) {
      for (const point of result.points) {
        if (typeof point.value === 'string' && !values.includes(point.value)) {
          values.push(point.value);
        }
      }
    }
    stateValues.value = values;
    state.value = 'ready';
    buildTextSummary();
    await nextTick();
    renderChart();
  } catch (caught) {
    if (seq !== requestSeq) {
      return;
    }
    error.value = caught as ApiError;
    state.value = 'error';
  }
}

function seriesNameFor(index: number): string {
  if (scopeDevice.value) {
    return props.metricKey;
  }
  const id = selectedIds.value[index];
  const component = id === undefined ? undefined : componentById(id);
  if (component === undefined) {
    return '未知组件';
  }
  return `${component.native_id}（${component.name || component.kind}）`;
}

function enumIndex(value: string): number {
  const index = stateValues.value.indexOf(value);
  return index === -1 ? 0 : index;
}

function convertPoints(result: DeviceMetricsSeriesResponse): (number | null)[] {
  if (isStateSeries.value) {
    return result.points.map((point) => {
      if (point.value === null || point.value === undefined || typeof point.value !== 'string') {
        return null;
      }
      return enumIndex(point.value);
    });
  }
  return result.points.map((point) => {
    if (typeof point.value !== 'number') {
      return null;
    }
    return Number.isFinite(point.value) ? point.value : null;
  });
}

function gaugeOption(pointsBySeries: DeviceMetricsSeriesResponse[]): echarts.EChartsCoreOption {
  const series = pointsBySeries.map((result, index) => ({
    name: seriesNameFor(index),
    type: 'line',
    data: convertPoints(result).map((value, pointIndex) => [
      new Date(result.points[pointIndex]!.timestamp).getTime(),
      value,
    ]),
    connectNulls: false,
    showSymbol: false,
    lineStyle: { width: 1.5 },
    emphasis: { focus: 'series' },
  }));
  return {
    animation: false,
    tooltip: {
      trigger: 'axis',
      valueFormatter: (value: unknown) =>
        typeof value === 'number' ? `${formatAxisNumber(value)} ${unitText.value}` : '—',
    },
    grid: { left: 70, right: 24, top: 30, bottom: 40 },
    xAxis: { type: 'time' },
    yAxis: { type: 'value', axisLabel: { formatter: formatAxisNumber } },
    series,
  };
}

function stateOption(pointsBySeries: DeviceMetricsSeriesResponse[]): echarts.EChartsCoreOption {
  const series = pointsBySeries.map((result, index) => ({
    name: seriesNameFor(index),
    type: 'line',
    step: 'end',
    data: convertPoints(result).map((value, pointIndex) => [
      new Date(result.points[pointIndex]!.timestamp).getTime(),
      value,
    ]),
    connectNulls: false,
    showSymbol: true,
    symbol: 'circle',
    symbolSize: 6,
    lineStyle: { width: 1.5 },
    emphasis: { focus: 'series' },
  }));
  return {
    animation: false,
    tooltip: {
      trigger: 'axis',
      valueFormatter: (value: unknown) => {
        if (typeof value !== 'number') {
          return '—';
        }
        const stateValue = stateValues.value[value] ?? '—';
        return enumDisplay(stateValue);
      },
    },
    grid: { left: 70, right: 24, top: 30, bottom: 40 },
    xAxis: { type: 'time' },
    yAxis: {
      type: 'category',
      data: stateValues.value.map((value) => enumDisplay(value)),
    },
    series,
  };
}

function enumDisplay(value: string): string {
  return lookupLabel(ENUM_VALUE_LABELS, value);
}

function renderChart(): void {
  if (chartContainer.value === null || chartFailed) {
    return;
  }
  try {
    if (chart === null) {
      try {
        chart = echarts.init(chartContainer.value);
      } catch {
        // 测试环境无画布等场景：图表不可用但保留文本摘要
        chartFailed = true;
        return;
      }
    }
    const option = isStateSeries.value
      ? stateOption(seriesResponses.value)
      : gaugeOption(seriesResponses.value);
    chart.setOption(option, true);
  } catch {
    // 渲染环境不支持（如无真实画布）：保留数据文本摘要，不把加载标记为失败
    chartFailed = true;
  }
}

function buildTextSummary(): void {
  const parts: string[] = [];
  seriesResponses.value.forEach((result, index) => {
    const seriesLabel = scopeDevice.value ? props.metricKey : seriesNameFor(index);
    if (isStateSeries.value) {
      // 状态/枚举系列不做数值最值统计：摘要展示当前状态与观测到的状态集合
      const statePoints = result.points.filter(
        (point): point is { timestamp: string; value: string; quality: string } =>
          typeof point.value === 'string' && point.value !== '',
      );
      if (statePoints.length === 0) {
        parts.push(`${seriesLabel}：尚无状态观测点`);
        return;
      }
      const last = statePoints[statePoints.length - 1]!.value;
      const seen = [...new Set(statePoints.map((point) => point.value))];
      parts.push(
        `${seriesLabel}：当前 ${enumDisplay(last)}；观测状态：${seen
          .map((value) => enumDisplay(value))
          .join('、')}`,
      );
      return;
    }
    const numbers = result.points
      .map((point) => point.value)
      .filter((value): value is number => typeof value === 'number');
    if (numbers.length === 0) {
      parts.push(`${seriesLabel}：无可用数值点`);
      return;
    }
    const max = Math.max(...numbers);
    const min = Math.min(...numbers);
    const last = numbers[numbers.length - 1]!;
    parts.push(
      `${seriesLabel}：当前 ${formatMetricValue(last)}，最高 ${formatMetricValue(max)}，最低 ${formatMetricValue(min)}${unitText.value ? ` ${unitText.value}` : ''}`,
    );
  });
  chartTextSummary.value = parts.join('；');
  const all = seriesResponses.value.flatMap((result) =>
    result.points.map(
      (point) => `${formatDateTime(point.timestamp)} ${formatMetricValue(point.value)}`,
    ),
  );
  chartPointsText.value = all.join('；');
}

function resize(): void {
  chart?.resize();
}

onMounted(() => {
  initSelectionAndLoad();
  window.addEventListener('resize', resize);
});

onBeforeUnmount(() => {
  window.removeEventListener('resize', resize);
  chart?.dispose();
  chart = null;
});
</script>

<template>
  <div class="metric-chart" data-testid="metric-chart">
    <div class="metric-chart__toolbar">
      <span class="metric-chart__metric-name">{{ metricKey }}</span>
      <el-radio-group v-model="rangeHours" size="small" data-testid="chart-range">
        <el-radio-button v-for="range in RANGES" :key="range.hours" :value="range.hours">
          {{ range.label }}
        </el-radio-button>
      </el-radio-group>
      <span v-if="resolutionLabel" class="metric-chart__resolution" data-testid="chart-resolution">
        分辨率：{{ resolutionLabel }}
      </span>
      <span v-if="unitText" class="metric-chart__unit">单位：{{ unitText }}</span>
    </div>

    <div
      v-if="!scopeDevice && candidateComponents.length > 1"
      class="metric-chart__components"
      data-testid="chart-components"
    >
      <el-checkbox-group v-model="selectedIds" :max="MAX_SERIES">
        <el-checkbox
          v-for="component in candidateComponents"
          :key="component.id"
          :value="component.id"
        >
          <span class="metric-chart__component-name">
            {{ component.native_id }}（{{ component.name || component.kind }}）
          </span>
        </el-checkbox>
      </el-checkbox-group>
      <span class="metric-chart__hint">最多选择 {{ MAX_SERIES }} 条序列</span>
    </div>

    <el-skeleton v-if="state === 'loading'" :rows="3" animated />
    <div v-else-if="state === 'error'" class="metric-chart__error">
      <p>指标趋势加载失败：{{ error?.message ?? '未知错误' }}</p>
      <p class="metric-chart__error-meta">
        错误码：{{ error?.code }} · 请求 ID：{{ error?.request_id }}
      </p>
      <el-button size="small" type="primary" plain @click="loadSeries">重试</el-button>
    </div>
    <p v-else-if="state === 'empty'" class="metric-chart__empty" data-testid="chart-empty">
      该时间范围内没有可绘制的数据点
    </p>
    <template v-else>
      <div ref="chartContainer" class="metric-chart__canvas" data-testid="chart-canvas" />
      <p v-if="chartFailed" class="metric-chart__fallback">
        当前环境不支持图表渲染，以下为数据文本摘要：
      </p>
      <ul class="metric-chart__summary" data-testid="chart-summary">
        <li v-for="(part, index) in chartTextSummary.split('；')" :key="index">{{ part }}</li>
      </ul>
      <p v-if="chartFailed" class="metric-chart__points">{{ chartPointsText }}</p>
    </template>
  </div>
</template>

<style scoped>
.metric-chart {
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 6px;
  padding: 12px;
  margin-bottom: 16px;
}
.metric-chart__toolbar {
  display: flex;
  align-items: center;
  gap: 14px;
  flex-wrap: wrap;
}
.metric-chart__metric-name {
  font-family: monospace;
  font-weight: 600;
}
.metric-chart__resolution,
.metric-chart__unit,
.metric-chart__hint {
  color: var(--warden-status-unknown);
  font-size: 12px;
}
.metric-chart__components {
  margin: 10px 0 4px;
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.metric-chart__component-name {
  font-family: monospace;
}
.metric-chart__canvas {
  width: 100%;
  height: 300px;
}
.metric-chart__error {
  color: var(--warden-status-critical);
  font-size: 13px;
}
.metric-chart__error-meta {
  color: var(--warden-status-unknown);
  font-size: 12px;
}
.metric-chart__empty {
  color: var(--warden-status-unknown);
  font-size: 13px;
  padding: 24px 0;
}
.metric-chart__summary {
  margin: 8px 0 0;
  padding: 0;
  list-style: none;
  color: var(--warden-status-unknown);
  font-size: 12px;
}
.metric-chart__fallback {
  margin: 10px 0 0;
  color: var(--warden-status-warning);
  font-size: 12px;
}
.metric-chart__points {
  margin: 4px 0 0;
  color: var(--warden-status-unknown);
  font-size: 11px;
  word-break: break-all;
  max-height: 90px;
  overflow: hidden;
}
</style>
