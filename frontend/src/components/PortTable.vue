<script setup lang="ts">
import { ElTable, ElTableColumn } from 'element-plus';

import type { ComponentView, LatestComponentGroup, LatestMetricItem } from '@/api/types';
import { METRIC_KEYS } from '@/api/generated/contracts';
import { ENUM_VALUE_LABELS, FRESHNESS_LABELS, METRIC_KEY_LABELS, label } from '@/lib/labels';
import { formatDateTimeSeconds } from '@/lib/format';
import { formatMetricValue, unitLabel } from '@/lib/format';

// M5T5 端口/部件表（UI_SPEC §5：大端口/组件列表分页、横向滚动时名称与
// 关键状态固定；PRODUCT_DESIGN §5.4-5.5：端口行 = 管理/运行状态、流量、
// 错误与丢包等每行最新指标 chips）。本组件只负责渲染：行数据来自
// /components（服务端分页），每行“最新指标”来自 /metrics/latest 按组件
// 分组的数据（父面板传入，键为组件 id）；没有成功观测的键绝不伪造值，
// 显示“尚无观测”。
const props = defineProps<{
  items: ComponentView[];
  latestByComponent: Record<string, LatestComponentGroup>;
}>();

// 组件行“关键状态”的指标键（每类端口的首要状态；光模块/其他部件无状态
// 键时退回组件自身状态）。映射是界面布局语义，指标键取自契约注册表。
const KIND_STATUS_METRIC: Record<string, string> = {
  interface: 'interface.oper_status',
  poe_port: 'poe.port.status',
};

type Tone = 'success' | 'warning' | 'danger' | 'info';

// 关键状态值 → 界面语义色（UI_SPEC §3：绿=正常态、琥珀=需注意、
// 红=故障、灰=非活动/未知）。不发明阈值：只对设备明确状态值着色。
const STATUS_VALUE_TONE: Record<string, Record<string, Tone>> = {
  'interface.oper_status': {
    up: 'success',
    down: 'info',
    not_present: 'info',
    unknown: 'info',
    testing: 'warning',
    dormant: 'warning',
    lower_layer_down: 'warning',
  },
  'poe.port.status': {
    on: 'success',
    off: 'info',
    denied: 'warning',
    fault: 'danger',
    unknown: 'info',
  },
};

function statusKeyOf(kind: string): string | null {
  return KIND_STATUS_METRIC[kind] ?? null;
}

/** 组件状态列（沿用 ComponentTable 的语义色约定）。 */
function componentStatusType(status: string): Tone {
  if (status === 'ok' || status === 'healthy' || status === 'normal' || status === 'optimal') {
    return 'success';
  }
  if (status === 'warning' || status === 'degraded') {
    return 'warning';
  }
  if (
    status === 'critical' ||
    status === 'failed' ||
    status === 'absent' ||
    status === 'detected' ||
    status === 'broken' ||
    status === 'fault'
  ) {
    return 'danger';
  }
  return 'info';
}

function statusDisplay(row: ComponentView): { text: string; tone: Tone } {
  const statusKey = statusKeyOf(row.kind);
  if (statusKey === null) {
    return { text: label(ENUM_VALUE_LABELS, row.status), tone: componentStatusType(row.status) };
  }
  const group = props.latestByComponent[row.id];
  const item = group?.metrics.find((metric) => metric.metric_key === statusKey);
  const raw = item?.value;
  if (typeof raw !== 'string') {
    return { text: '尚无观测', tone: 'info' };
  }
  const tone = STATUS_VALUE_TONE[statusKey]?.[raw] ?? 'info';
  return { text: label(ENUM_VALUE_LABELS, raw), tone };
}

function metricOrderIndex(key: string): number {
  const index = METRIC_KEYS.indexOf(key as (typeof METRIC_KEYS)[number]);
  return index === -1 ? METRIC_KEYS.length : index;
}

function groupItems(row: ComponentView): LatestMetricItem[] {
  const group = props.latestByComponent[row.id];
  if (group === undefined) {
    return [];
  }
  return [...group.metrics].sort(
    (first, second) => metricOrderIndex(first.metric_key) - metricOrderIndex(second.metric_key),
  );
}

function chipValue(item: LatestMetricItem): string {
  const raw = item.value;
  if (raw === null || raw === undefined) {
    return '—';
  }
  if (typeof raw === 'boolean') {
    return raw ? '是' : '否';
  }
  if (typeof raw === 'string') {
    return label(ENUM_VALUE_LABELS, raw);
  }
  return formatMetricValue(raw);
}

function chipValueTone(item: LatestMetricItem): string {
  if (typeof item.value === 'string') {
    if (
      ['critical', 'failed', 'detected', 'fault', 'broken', 'low_battery'].includes(item.value)
    ) {
      return 'port-table__chip-value--danger';
    }
    if (['warning', 'degraded', 'on_battery', 'communication_lost'].includes(item.value)) {
      return 'port-table__chip-value--warning';
    }
    if (['unknown'].includes(item.value)) {
      return 'port-table__chip-value--unknown';
    }
  }
  return '';
}

function freshnessClass(freshness: string): string {
  return `port-table__dot--${freshness}`;
}

function chipTitle(item: LatestMetricItem): string {
  const chipLabel = label(METRIC_KEY_LABELS, item.metric_key);
  return (
    `${chipLabel}：${chipValue(item)} · 观测时间 ${formatDateTimeSeconds(item.observed_at)} · ` +
    `新鲜度 ${label(FRESHNESS_LABELS, item.freshness)}`
  );
}
</script>

<template>
  <el-table
    class="port-table"
    :data="items"
    row-key="id"
    data-testid="port-table"
    size="default"
  >
    <el-table-column label="端口/部件" min-width="220" fixed="left">
      <template #default="{ row }">
        <div class="port-table__name">{{ row.name || row.native_id || '—' }}</div>
        <div class="port-table__sub">{{ row.kind }} · {{ row.native_id || '—' }}</div>
      </template>
    </el-table-column>
    <el-table-column label="状态" width="120" fixed="left">
      <template #default="{ row }">
        <span
          class="port-table__status"
          :class="`port-table__status--${statusDisplay(row as ComponentView).tone}`"
          data-testid="port-status"
        >
          {{ statusDisplay(row as ComponentView).text }}
        </span>
      </template>
    </el-table-column>
    <el-table-column label="最新指标" min-width="560">
      <template #default="{ row }">
        <div v-if="groupItems(row as ComponentView).length > 0" class="port-table__chips">
          <span
            v-for="item in groupItems(row as ComponentView)"
            :key="`${row.id}-${item.metric_key}`"
            class="port-table__chip"
            :data-testid="`port-chip-${item.metric_key}`"
            :title="chipTitle(item)"
          >
            <span
              class="port-table__dot"
              :class="freshnessClass(item.freshness)"
              :title="`新鲜度：${label(FRESHNESS_LABELS, item.freshness)}`"
            />
            <span class="port-table__chip-label">{{ label(METRIC_KEY_LABELS, item.metric_key) }}</span>
            <span class="port-table__chip-value" :class="chipValueTone(item)">
              {{ chipValue(item) }}
              <span v-if="item.unit" class="port-table__chip-unit">{{ unitLabel(item.unit) }}</span>
            </span>
          </span>
        </div>
        <span v-else class="port-table__none" data-testid="port-no-observation">
          尚无观测（该组件尚无一次成功观测）
        </span>
      </template>
    </el-table-column>
  </el-table>
</template>

<style scoped>
.port-table__name {
  font-weight: 600;
}
.port-table__sub {
  color: var(--warden-status-unknown);
  font-size: 12px;
  font-family: monospace;
}
.port-table__status {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 3px;
  font-size: 12px;
  border: 1px solid transparent;
  white-space: nowrap;
}
.port-table__status--success {
  color: var(--warden-status-healthy);
  border-color: var(--warden-status-healthy);
}
.port-table__status--warning {
  color: var(--warden-status-warning);
  border-color: var(--warden-status-warning);
}
.port-table__status--danger {
  color: var(--warden-status-critical);
  border-color: var(--warden-status-critical);
}
.port-table__status--info {
  color: var(--warden-status-unknown);
  border-color: var(--warden-status-unknown);
}
.port-table__chips {
  display: flex;
  flex-wrap: wrap;
  gap: 6px 14px;
}
.port-table__chip {
  display: inline-flex;
  align-items: baseline;
  gap: 5px;
  font-size: 12px;
  white-space: nowrap;
}
.port-table__dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  align-self: center;
  flex: none;
  background: var(--warden-status-unknown);
}
.port-table__dot--fresh {
  background: var(--warden-status-healthy);
}
.port-table__dot--stale {
  background: var(--warden-status-warning);
}
.port-table__dot--expired {
  background: var(--warden-status-critical);
}
.port-table__chip-label {
  color: var(--warden-status-unknown);
}
.port-table__chip-value {
  font-family: monospace;
}
.port-table__chip-value--danger {
  color: var(--warden-status-critical);
}
.port-table__chip-value--warning {
  color: var(--warden-status-warning);
}
.port-table__chip-value--unknown {
  color: var(--warden-status-unknown);
}
.port-table__chip-unit {
  color: var(--warden-status-unknown);
  margin-left: 2px;
}
.port-table__none {
  color: var(--warden-status-unknown);
  font-size: 12px;
}
</style>
