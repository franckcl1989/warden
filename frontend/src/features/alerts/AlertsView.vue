<script setup lang="ts">
import {
  ElButton,
  ElDrawer,
  ElInput,
  ElOption,
  ElRadioButton,
  ElRadioGroup,
  ElSelect,
  ElTable,
  ElTableColumn,
} from 'element-plus';
import { onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import AsyncState from '@/components/AsyncState.vue';
import PaginationBar from '@/components/PaginationBar.vue';
import SeverityBadge from '@/components/SeverityBadge.vue';
import type { ApiError } from '@/api/client';
import { request } from '@/api/client';
import type { AlertDetailItem, AlertListItem, AlertsListResponse } from '@/api/types';
import { formatDateTime } from '@/lib/format';
import { label, DEVICE_TYPE_LABELS, ALERT_STATUS_LABELS } from '@/lib/labels';
import { registerCacheEntry } from '@/lib/query-cache';

// 当前问题页（PLT-04，PRODUCT_DESIGN §6.4）：未恢复/已恢复切换 + 筛选；
// 行 → 详情抽屉（证据 + 时间线）。当前问题由引擎状态/离线/过期产生。
const route = useRoute();
const router = useRouter();

const status = ref<string>(
  typeof route.query['status'] === 'string' ? String(route.query['status']) : 'active',
);
const severityFilter = ref<string | null>(
  typeof route.query['severity'] === 'string' ? String(route.query['severity']) : null,
);
const ruleFilter = ref<string | null>(null);
const page = ref(1);
const pageSize = ref(20);

const state = ref<'loading' | 'ready' | 'empty' | 'error' | 'permission_denied'>('loading');
const error = ref<ApiError | null>(null);
const response = ref<AlertsListResponse | null>(null);

const drawerOpen = ref(false);
const detailState = ref<'loading' | 'ready' | 'error' | 'permission_denied' | 'not_found'>(
  'loading',
);
const detailError = ref<ApiError | null>(null);
const detail = ref<AlertDetailItem | null>(null);

function pushQuery(): void {
  const query = { ...route.query } as Record<string, string | null>;
  if (status.value === 'active') {
    delete query['status'];
  } else {
    query['status'] = status.value;
  }
  if (severityFilter.value !== null) {
    query['severity'] = severityFilter.value;
  } else {
    delete query['severity'];
  }
  if (ruleFilter.value) {
    query['rule_key'] = ruleFilter.value;
  } else {
    delete query['rule_key'];
  }
  const sorted = (entries: [string, unknown][]): string =>
    JSON.stringify(entries.sort(([a], [b]) => a.localeCompare(b)));
  if (sorted(Object.entries(query)) === sorted(Object.entries(route.query))) {
    void load();
    return;
  }
  void router.replace({ query });
}

async function load(): Promise<void> {
  state.value = 'loading';
  error.value = null;
  try {
    const params = new URLSearchParams({
      page: String(page.value),
      page_size: String(pageSize.value),
      status: status.value,
    });
    if (severityFilter.value) params.set('severity', severityFilter.value);
    if (ruleFilter.value) params.set('rule_key', ruleFilter.value);
    const result = await request<AlertsListResponse>(`/alerts?${params}`);
    response.value = result;
    state.value = result.total === 0 ? 'empty' : 'ready';
  } catch (caught) {
    error.value = caught as ApiError;
    state.value = error.value.code === 'permission_denied' ? 'permission_denied' : 'error';
  }
}

function emptyText(): string {
  if (severityFilter.value !== null || ruleFilter.value !== null) {
    return '筛选无结果';
  }
  return status.value === 'active' ? '当前没有未恢复的问题' : '当前没有已恢复问题';
}

function onStatusChange(): void {
  page.value = 1;
  pushQuery();
}

function onSeverityChange(): void {
  page.value = 1;
  pushQuery();
}

function onRuleChange(): void {
  page.value = 1;
  pushQuery();
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

async function openDrawer(row: AlertListItem): Promise<void> {
  drawerOpen.value = true;
  lastAlertId.value = row.id;
  await loadDetail(row.id);
}

async function loadDetail(alertId: string): Promise<void> {
  detailState.value = 'loading';
  detailError.value = null;
  detail.value = null;
  try {
    const result = await request<AlertDetailItem>(`/alerts/${alertId}`);
    detail.value = result;
    detailState.value = 'ready';
  } catch (caught) {
    detailError.value = caught as ApiError;
    if (detailError.value.code === 'permission_denied') {
      detailState.value = 'permission_denied';
    } else if (detailError.value.code === 'resource_not_found') {
      detailState.value = 'not_found';
    } else {
      detailState.value = 'error';
    }
  }
}

function closeDrawer(): void {
  drawerOpen.value = false;
}

const lastAlertId = ref<string | null>(null);

function retryDetail(): void {
  if (lastAlertId.value !== null) {
    void loadDetail(lastAlertId.value);
  }
}

function evidenceLines(): string[] {
  const evidence = detail.value?.evidence;
  if (evidence === undefined || evidence === null) {
    return [];
  }
  return Object.entries(evidence).map(([key, value]) => `${key}: ${String(value)}`);
}

let unregister: (() => void) | null = null;

// 页面级筛选写入 URL query（UI_SPEC §2）：本地变更 → pushQuery → 路由变化 →
// 从这里统一重取；浏览器前进/后退也走同一条路径。
watch(
  () => [route.query['status'], route.query['severity'], route.query['rule_key']] as const,
  ([nextStatus, nextSeverity, nextRule]) => {
    const statusValue = typeof nextStatus === 'string' ? nextStatus : 'active';
    const severityValue = typeof nextSeverity === 'string' ? nextSeverity : null;
    const ruleValue = typeof nextRule === 'string' ? nextRule : null;
    if (statusValue !== status.value) {
      status.value = statusValue;
    }
    if (severityValue !== severityFilter.value) {
      severityFilter.value = severityValue;
    }
    if (ruleValue !== ruleFilter.value) {
      ruleFilter.value = ruleValue;
    }
    void load();
  },
);

onMounted(() => {
  void load();
  unregister = registerCacheEntry({ kind: 'alerts', refetch: () => void load() });
});

onBeforeUnmount(() => {
  unregister?.();
});
</script>

<template>
  <div class="alerts-page" data-testid="alerts-page">
    <div class="alerts-page__toolbar">
      <el-radio-group v-model="status" data-testid="alert-status-toggle" @change="onStatusChange">
        <el-radio-button value="active">未恢复</el-radio-button>
        <el-radio-button value="resolved">已恢复</el-radio-button>
      </el-radio-group>
      <el-select
        v-model="severityFilter"
        placeholder="严重级别"
        clearable
        class="alerts-page__filter"
        data-testid="filter-severity"
        @change="onSeverityChange"
      >
        <el-option value="critical" label="严重" />
        <el-option value="warning" label="警告" />
      </el-select>
      <el-input
        v-model="ruleFilter"
        placeholder="按规则键筛选"
        clearable
        class="alerts-page__filter"
        data-testid="filter-rule"
        @keyup.enter="onRuleChange"
        @clear="onRuleChange"
      />
    </div>

    <AsyncState :state="state" :error="error" :empty-text="emptyText()" @retry="load">
      <el-table
        v-if="(response?.items ?? []).length > 0"
        :data="(response?.items ?? []) as AlertListItem[]"
        row-key="id"
        data-testid="alerts-table"
        @row-click="openDrawer"
      >
        <el-table-column label="严重级别" width="90">
          <template #default="{ row }"><SeverityBadge :severity="row.severity" /></template>
        </el-table-column>
        <el-table-column label="设备" min-width="150">
          <template #default="{ row }">
            <div>{{ row.device.name }}</div>
            <div class="alerts-page__sub">
              {{ label(DEVICE_TYPE_LABELS, row.device.device_type) }}
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="title" label="问题" min-width="220" />
        <el-table-column label="规则键" min-width="130">
          <template #default="{ row }"
            ><code>{{ row.rule_key }}</code></template
          >
        </el-table-column>
        <el-table-column label="状态" width="90">
          <template #default="{ row }">{{ label(ALERT_STATUS_LABELS, row.status) }}</template>
        </el-table-column>
        <el-table-column label="首次发生" width="150">
          <template #default="{ row }">{{ formatDateTime(row.first_occurred_at) }}</template>
        </el-table-column>
        <el-table-column label="最近发生" width="150">
          <template #default="{ row }">{{ formatDateTime(row.last_occurred_at) }}</template>
        </el-table-column>
        <el-table-column v-if="status === 'resolved'" label="已恢复" width="150">
          <template #default="{ row }">{{ formatDateTime(row.resolved_at) }}</template>
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

    <el-drawer v-model="drawerOpen" title="问题详情" size="520px" @close="closeDrawer">
      <AsyncState :state="detailState" :error="detailError" @retry="retryDetail">
        <template v-if="detail">
          <h3 class="alerts-page__detail-title">{{ detail.title }}</h3>
          <dl class="alerts-page__detail-list">
            <div>
              <dt>设备</dt>
              <dd>{{ detail.device.name }}</dd>
            </div>
            <div>
              <dt>严重级别</dt>
              <dd><SeverityBadge :severity="detail.severity" /></dd>
            </div>
            <div>
              <dt>状态</dt>
              <dd>{{ label(ALERT_STATUS_LABELS, detail.status) }}</dd>
            </div>
            <div>
              <dt>规则键</dt>
              <dd>
                <code>{{ detail.rule_key }}</code>
              </dd>
            </div>
            <div>
              <dt>去重键</dt>
              <dd>
                <code>{{ detail.dedupe_key }}</code>
              </dd>
            </div>
            <div v-if="detail.component_id">
              <dt>组件</dt>
              <dd>
                <code>{{ detail.component_id }}</code>
              </dd>
            </div>
            <div>
              <dt>信号次数</dt>
              <dd>{{ detail.signal_count }}</dd>
            </div>
            <div>
              <dt>首次发生</dt>
              <dd>{{ formatDateTime(detail.first_occurred_at) }}</dd>
            </div>
            <div>
              <dt>最近发生</dt>
              <dd>{{ formatDateTime(detail.last_occurred_at) }}</dd>
            </div>
            <div v-if="detail.resolved_at">
              <dt>已恢复</dt>
              <dd>{{ formatDateTime(detail.resolved_at) }}</dd>
            </div>
          </dl>
          <h4 class="alerts-page__detail-sub">证据</h4>
          <AsyncState
            :state="evidenceLines().length > 0 ? 'ready' : 'empty'"
            empty-text="无附加证据"
          >
            <ul class="alerts-page__evidence">
              <li v-for="line in evidenceLines()" :key="line">{{ line }}</li>
            </ul>
          </AsyncState>
        </template>
      </AsyncState>
      <template #footer>
        <el-button @click="closeDrawer">关闭</el-button>
      </template>
    </el-drawer>
  </div>
</template>

<style scoped>
.alerts-page__toolbar {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-bottom: 12px;
}
.alerts-page__filter {
  width: 200px;
}
.alerts-page__sub {
  color: var(--warden-status-unknown);
  font-size: 12px;
}
.alerts-page__detail-title {
  margin: 0 0 12px;
  font-size: 16px;
}
.alerts-page__detail-list {
  margin: 0 0 16px;
}
.alerts-page__detail-list div {
  display: flex;
  gap: 12px;
  padding: 6px 0;
  border-bottom: 1px solid var(--el-border-color-lighter);
  font-size: 13px;
}
.alerts-page__detail-list dt {
  color: var(--warden-status-unknown);
  width: 100px;
  flex-shrink: 0;
}
.alerts-page__detail-list dd {
  margin: 0;
}
.alerts-page__detail-sub {
  margin: 0 0 8px;
  font-size: 14px;
}
.alerts-page__evidence {
  margin: 0;
  padding-left: 18px;
  font-size: 13px;
  font-family: monospace;
  word-break: break-all;
}
</style>
