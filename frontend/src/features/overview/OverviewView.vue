<script setup lang="ts">
import { ElButton } from 'element-plus';
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';

import AsyncState from '@/components/AsyncState.vue';
import OperationState from '@/components/OperationState.vue';
import SeverityBadge from '@/components/SeverityBadge.vue';
import type { ApiError } from '@/api/client';
import { request } from '@/api/client';
import type {
  AttentionItem,
  OperationTaskView,
  OperationsListResponse,
  OverviewResponse,
} from '@/api/types';
import { DEVICE_TYPE_LABELS, label } from '@/lib/labels';
import { formatDateTime } from '@/lib/format';
import { registerCacheEntry } from '@/lib/query-cache';
import { useRealtimeStore } from '@/stores/realtime';

// 总览页（PLT-03，PRODUCT_DESIGN §3 / UI_SPEC §6）：
// 顶部统计、设备类型四卡、需要关注（按服务端顺序原样渲染）、最近任务。
// /overview 与 /operations 均为真实数据；SSE 刷新不整体闪骨架屏。
const router = useRouter();
const realtime = useRealtimeStore();

const state = ref<'loading' | 'ready' | 'error' | 'permission_denied'>('loading');
const refreshing = ref(false);
const error = ref<ApiError | null>(null);
const overview = ref<OverviewResponse | null>(null);
const recentOperations = ref<OperationTaskView[]>([]);

const DEVICE_TYPES = ['server', 'synology_nas', 'core_switch', 'access_switch'];

async function load(silent = false): Promise<void> {
  if (silent) {
    refreshing.value = true;
  } else {
    state.value = 'loading';
  }
  error.value = null;
  try {
    const [overviewResult, operationsResult] = await Promise.all([
      request<OverviewResponse>('/overview'),
      request<OperationsListResponse>('/operations?page=1&page_size=5'),
    ]);
    overview.value = overviewResult;
    recentOperations.value = operationsResult.items ?? [];
    state.value = 'ready';
  } catch (caught) {
    error.value = caught as ApiError;
    if (!silent) {
      state.value = error.value.code === 'permission_denied' ? 'permission_denied' : 'error';
    }
  } finally {
    refreshing.value = false;
  }
}

let unregister: (() => void) | null = null;

onMounted(() => {
  void load();
  unregister = registerCacheEntry({ kind: 'overview', refetch: () => void load(true) });
});

onBeforeUnmount(() => {
  unregister?.();
});

function count(map: Record<string, number> | undefined, key: string): number {
  if (map === undefined) {
    return 0;
  }
  return typeof map[key] === 'number' ? map[key] : 0;
}

const stats = computed(() => overview.value?.stats);
const asOf = computed(() => overview.value?.as_of ?? null);

function goTypeDevices(deviceType: string): void {
  void router.push({ name: 'devices', query: { device_type: deviceType } });
}

function goDevice(id: string): void {
  void router.push({ name: 'device-detail', params: { id } });
}

function goOperation(id: string): void {
  void router.push({ name: 'operations-detail', params: { id } });
}

function connectionText(): string {
  if (realtime.connectionState === 'connected') {
    return '实时连接正常';
  }
  if (realtime.connectionState === 'degraded') {
    return '实时连接断开，15 秒轮询中';
  }
  return '实时未连接';
}

function attentionProblemsText(item: AttentionItem): string {
  return item.problems.map((problem) => `${problem.title}`).join('；');
}
</script>

<template>
  <div class="overview-page" data-testid="overview-page">
    <div class="overview-page__meta">
      <span v-if="asOf" data-testid="overview-as-of">数据截至：{{ formatDateTime(asOf) }}</span>
      <span v-if="refreshing" class="overview-page__refreshing">刷新中…</span>
      <span
        class="overview-page__connection"
        :class="{ 'overview-page__connection--degraded': realtime.connectionState === 'degraded' }"
      >
        {{ connectionText() }}
      </span>
    </div>

    <AsyncState :state="state" :error="error" @retry="load">
      <template v-if="overview">
        <section class="overview-page__stats" data-testid="overview-stats">
          <div class="overview-page__stat-card">
            <span class="overview-page__stat-value">{{ stats?.device_total ?? 0 }}</span>
            <span class="overview-page__stat-label">设备总数</span>
          </div>
          <div class="overview-page__stat-card">
            <span class="overview-page__stat-value overview-page__stat-value--online">
              {{ count(stats?.reachability, 'online') }}
            </span>
            <span class="overview-page__stat-label">在线</span>
          </div>
          <div class="overview-page__stat-card">
            <span class="overview-page__stat-value overview-page__stat-value--offline">
              {{ count(stats?.reachability, 'offline') }}
            </span>
            <span class="overview-page__stat-label">离线</span>
          </div>
          <div class="overview-page__stat-card">
            <span class="overview-page__stat-value">{{
              count(stats?.reachability, 'unknown')
            }}</span>
            <span class="overview-page__stat-label">可达性未知</span>
          </div>
          <div class="overview-page__stat-card">
            <span class="overview-page__stat-value overview-page__stat-value--healthy">
              {{ count(stats?.health, 'healthy') }}
            </span>
            <span class="overview-page__stat-label">健康</span>
          </div>
          <div class="overview-page__stat-card">
            <span class="overview-page__stat-value overview-page__stat-value--warning">
              {{ count(stats?.health, 'warning') }}
            </span>
            <span class="overview-page__stat-label">警告</span>
          </div>
          <div class="overview-page__stat-card">
            <span class="overview-page__stat-value overview-page__stat-value--critical">
              {{ count(stats?.health, 'critical') }}
            </span>
            <span class="overview-page__stat-label">严重</span>
          </div>
          <div class="overview-page__stat-card">
            <span class="overview-page__stat-value">{{ count(stats?.health, 'unknown') }}</span>
            <span class="overview-page__stat-label">健康未知</span>
          </div>
          <div class="overview-page__stat-card">
            <span class="overview-page__stat-value overview-page__stat-value--critical">
              {{ stats?.active_critical_alerts ?? 0 }}
            </span>
            <span class="overview-page__stat-label">严重当前问题</span>
          </div>
          <div class="overview-page__stat-card">
            <span class="overview-page__stat-value overview-page__stat-value--running">
              {{ stats?.operations_running ?? 0 }}
            </span>
            <span class="overview-page__stat-label">运行中任务</span>
          </div>
          <div class="overview-page__stat-card">
            <span class="overview-page__stat-value overview-page__stat-value--verification">
              {{ stats?.operations_verification_required ?? 0 }}
            </span>
            <span class="overview-page__stat-label">待核验任务</span>
          </div>
        </section>

        <section class="overview-page__types" data-testid="overview-types">
          <article
            v-for="deviceType in DEVICE_TYPES"
            :key="deviceType"
            class="overview-page__type-card"
            :data-testid="`type-card-${deviceType}`"
            @click="goTypeDevices(deviceType)"
          >
            <h3>{{ label(DEVICE_TYPE_LABELS, deviceType) }}</h3>
            <dl class="overview-page__type-stats">
              <div>
                <dt>在线</dt>
                <dd>{{ count(overview.device_types?.[deviceType]?.reachability, 'online') }}</dd>
              </div>
              <div>
                <dt>离线</dt>
                <dd class="overview-page__type-offline">
                  {{ count(overview.device_types?.[deviceType]?.reachability, 'offline') }}
                </dd>
              </div>
              <div>
                <dt>健康</dt>
                <dd>{{ count(overview.device_types?.[deviceType]?.health, 'healthy') }}</dd>
              </div>
              <div>
                <dt>警告</dt>
                <dd class="overview-page__type-warning">
                  {{ count(overview.device_types?.[deviceType]?.health, 'warning') }}
                </dd>
              </div>
              <div>
                <dt>严重</dt>
                <dd class="overview-page__type-critical">
                  {{ count(overview.device_types?.[deviceType]?.health, 'critical') }}
                </dd>
              </div>
            </dl>
          </article>
        </section>

        <section class="overview-page__attention" data-testid="overview-attention">
          <h2 class="overview-page__heading">需要关注</h2>
          <AsyncState
            :state="overview.attention.length > 0 ? 'ready' : 'empty'"
            empty-text="当前没有需要关注的设备"
          >
            <table class="overview-page__table">
              <thead>
                <tr>
                  <th>设备</th>
                  <th>类型/型号</th>
                  <th>问题摘要</th>
                  <th>最近采集</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="item in overview.attention" :key="item.device.id">
                  <td>
                    <button
                      type="button"
                      class="overview-page__link"
                      data-testid="attention-device"
                      @click="goDevice(item.device.id)"
                    >
                      {{ item.device.name }}
                    </button>
                  </td>
                  <td>
                    {{ label(DEVICE_TYPE_LABELS, item.device.device_type) }}
                    <span v-if="item.device.vendor || item.device.model">
                      · {{ item.device.vendor ?? '—' }} {{ item.device.model ?? '' }}
                    </span>
                  </td>
                  <td>
                    <div
                      v-for="problem in item.problems"
                      :key="problem.id"
                      class="overview-page__problem"
                    >
                      <SeverityBadge :severity="problem.severity" />
                      <span>{{ problem.title }}</span>
                      <code>{{ problem.rule_key }}</code>
                    </div>
                    <span v-if="item.problems.length === 0">{{ attentionProblemsText(item) }}</span>
                  </td>
                  <td>{{ formatDateTime(item.last_collected_at) }}</td>
                  <td>
                    <el-button size="small" @click="goDevice(item.device.id)">详情</el-button>
                  </td>
                </tr>
              </tbody>
            </table>
          </AsyncState>
        </section>

        <section class="overview-page__recent" data-testid="overview-recent">
          <h2 class="overview-page__heading">最近任务</h2>
          <AsyncState
            :state="recentOperations.length > 0 ? 'ready' : 'empty'"
            empty-text="暂无人工操作任务"
          >
            <table class="overview-page__table">
              <thead>
                <tr>
                  <th>动作</th>
                  <th>设备</th>
                  <th>发起人</th>
                  <th>状态</th>
                  <th>开始时间</th>
                  <th>结果摘要</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="operation in recentOperations"
                  :key="operation.id"
                  class="overview-page__row-clickable"
                  @click="goOperation(operation.id)"
                >
                  <td>
                    <button
                      type="button"
                      class="overview-page__link"
                      @click="goOperation(operation.id)"
                    >
                      {{ operation.requirement_id }} {{ operation.capability_key }}
                    </button>
                  </td>
                  <td>{{ operation.device.name }}</td>
                  <td>{{ operation.requested_by.username }}</td>
                  <td><OperationState :state="operation.state" /></td>
                  <td>{{ formatDateTime(operation.started_at ?? operation.created_at) }}</td>
                  <td>{{ operation.result_summary ?? '—' }}</td>
                </tr>
              </tbody>
            </table>
          </AsyncState>
        </section>
      </template>
    </AsyncState>
  </div>
</template>

<style scoped>
.overview-page__meta {
  display: flex;
  gap: 16px;
  align-items: center;
  color: var(--warden-status-unknown);
  font-size: 12px;
  margin-bottom: 10px;
}
.overview-page__refreshing {
  color: var(--warden-status-running);
}
.overview-page__connection--degraded {
  color: var(--warden-status-warning);
}
.overview-page__stats {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(130px, 1fr));
  gap: 10px;
  margin-bottom: 18px;
}
.overview-page__stat-card {
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 6px;
  padding: 12px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.overview-page__stat-value {
  font-size: 24px;
  font-weight: 700;
  font-family: monospace;
}
.overview-page__stat-value--online,
.overview-page__stat-value--healthy {
  color: var(--warden-status-healthy);
}
.overview-page__stat-value--offline,
.overview-page__stat-value--critical {
  color: var(--warden-status-critical);
}
.overview-page__stat-value--warning {
  color: var(--warden-status-warning);
}
.overview-page__stat-value--running {
  color: var(--warden-status-running);
}
.overview-page__stat-value--verification {
  color: var(--warden-status-verification);
}
.overview-page__stat-label {
  color: var(--warden-status-unknown);
  font-size: 12px;
}
.overview-page__types {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 12px;
  margin-bottom: 18px;
}
.overview-page__type-card {
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 6px;
  padding: 12px 16px;
  cursor: pointer;
}
.overview-page__type-card h3 {
  margin: 0 0 8px;
  font-size: 15px;
}
.overview-page__type-stats {
  display: flex;
  gap: 18px;
  margin: 0;
  font-size: 13px;
}
.overview-page__type-stats dt {
  color: var(--warden-status-unknown);
  font-size: 12px;
}
.overview-page__type-stats dd {
  margin: 0;
  font-family: monospace;
}
.overview-page__type-offline {
  color: var(--warden-status-critical);
}
.overview-page__type-warning {
  color: var(--warden-status-warning);
}
.overview-page__type-critical {
  color: var(--warden-status-critical);
}
.overview-page__heading {
  font-size: 16px;
  margin: 0 0 10px;
}
.overview-page__attention {
  margin-bottom: 22px;
}
.overview-page__table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
.overview-page__table th,
.overview-page__table td {
  text-align: left;
  padding: 8px 10px;
  border-bottom: 1px solid var(--el-border-color-lighter);
  vertical-align: top;
}
.overview-page__table th {
  color: var(--warden-status-unknown);
  font-weight: 500;
}
.overview-page__row-clickable {
  cursor: pointer;
}
.overview-page__problem {
  display: flex;
  gap: 8px;
  align-items: center;
  padding: 2px 0;
}
.overview-page__problem code {
  color: var(--warden-status-unknown);
  font-size: 11px;
}
.overview-page__link {
  border: none;
  background: none;
  color: var(--el-color-primary);
  cursor: pointer;
  padding: 0;
  font-size: 13px;
}
</style>
