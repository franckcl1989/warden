<script setup lang="ts">
import { ElAlert, ElLink } from 'element-plus';
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';

import AsyncState from '@/components/AsyncState.vue';
import type { ApiError } from '@/api/client';
import { request } from '@/api/client';
import type {
  CollectionFailureView,
  ComponentsView,
  SystemStatusResponse,
} from '@/api/types';
import { formatDateTime, formatDuration } from '@/lib/format';
import {
  COLLECTION_TYPE_LABELS,
  SYSTEM_COMPONENT_LABELS,
  SYSTEM_COMPONENT_STATUS_LABELS,
  label,
} from '@/lib/labels';
import { registerCacheEntry } from '@/lib/query-cache';
import { useAuthStore } from '@/stores/auth';

// 系统状态页（PLT-08，PRODUCT_DESIGN §2 只读查看 API/Worker/数据库/文件存储/
// 接收器状态；ARCHITECTURE.md §9）。仅管理员可访问（路由 adminOnly + 服务端
// system.read）。SSE system.status_changed / reset / 轮询通过 query-cache
// kind 'system' 触发静默重取（UI_SPEC §11）。
const router = useRouter();
const auth = useAuthStore();

const state = ref<'loading' | 'ready' | 'error' | 'permission_denied'>('loading');
const error = ref<ApiError | null>(null);
const status = ref<SystemStatusResponse | null>(null);
const refreshing = ref(false);

const isAdmin = computed(() => auth.isAdmin);

async function load(silent = false): Promise<void> {
  if (!isAdmin.value) {
    state.value = 'permission_denied';
    return;
  }
  if (silent) {
    refreshing.value = true;
  } else {
    state.value = 'loading';
  }
  error.value = null;
  try {
    status.value = await request<SystemStatusResponse>('/system/status');
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
  unregister = registerCacheEntry({ kind: 'system', refetch: () => void load(true) });
});

onBeforeUnmount(() => {
  unregister?.();
});

const maintenance = computed(() => status.value?.maintenance);
const components = computed(() => status.value?.components);

/** 组件行（worker/ingest 携带的额外字段直接内联展示，不伪造统一形状）。 */
function componentRows(): Array<{ key: keyof ComponentsView; note: string }> {
  if (!components.value) {
    return [];
  }
  return [
    { key: 'api', note: '' },
    { key: 'database', note: '' },
    { key: 'file_storage', note: '' },
    { key: 'worker', note: workerNote() },
    { key: 'ingest', note: ingestNote() },
  ];
}

function workerNote(): string {
  const worker = components.value?.worker;
  if (!worker) {
    return '';
  }
  const parts: string[] = [];
  if (worker.detail) {
    parts.push(worker.detail);
  }
  if (worker.last_activity_at !== null && worker.last_activity_at !== undefined) {
    parts.push(`最近活动：${formatDateTime(worker.last_activity_at)}`);
  }
  if (worker.collection_lag_seconds !== null && worker.collection_lag_seconds !== undefined) {
    parts.push(`采集领取延迟：${formatDuration(worker.collection_lag_seconds)}`);
  }
  return parts.join('；');
}

function ingestNote(): string {
  const ingest = components.value?.ingest;
  if (!ingest) {
    return '';
  }
  const parts: string[] = [];
  if (ingest.detail) {
    parts.push(ingest.detail);
  }
  parts.push(`累计接收事件：${ingest.events_received_total}`);
  if (ingest.last_received_at !== null && ingest.last_received_at !== undefined) {
    parts.push(`最近接收：${formatDateTime(ingest.last_received_at)}`);
  } else {
    parts.push('最近接收：—（尚无事件，属正常空闲）');
  }
  return parts.join('；');
}

function goOperations(stateFilter: string): void {
  void router.push({ name: 'operations', query: { state: stateFilter } });
}

function failureText(failure: CollectionFailureView): string {
  return `${failure.device_name}（${label(COLLECTION_TYPE_LABELS, failure.collection_type)}）`;
}
</script>

<template>
  <div class="system-page" data-testid="system-page">
    <div class="system-page__meta">
      <span v-if="status?.as_of" data-testid="system-as-of">
        数据截至：{{ formatDateTime(status.as_of) }}
      </span>
      <span v-if="refreshing" class="system-page__refreshing">刷新中…</span>
    </div>

    <AsyncState :state="state" :error="error" @retry="load">
      <template v-if="status">
        <el-alert
          v-if="maintenance?.active"
          type="error"
          :closable="false"
          show-icon
          class="system-page__maintenance"
          data-testid="maintenance-banner"
          title="维护模式中：已暂停新建操作任务与远程连接"
        >
          <span>
            自 {{ formatDateTime(maintenance.since) }} 起
            <template v-if="maintenance.reason">，原因：{{ maintenance.reason }}</template>
            。维护模式由宿主机命令开启/关闭（Web 界面只读显示）。
          </span>
        </el-alert>

        <section class="system-page__card" data-testid="components-card">
          <h3 class="system-page__card-title">组件状态</h3>
          <ul class="system-page__component-list">
            <li
              v-for="row in componentRows()"
              :key="row.key"
              class="system-page__component-row"
              :data-testid="`component-${row.key}`"
            >
              <span class="system-page__component-name">
                {{ label(SYSTEM_COMPONENT_LABELS, row.key) }}
              </span>
              <span
                class="system-page__status"
                :class="`system-page__status--${components?.[row.key]?.status}`"
              >
                {{ label(SYSTEM_COMPONENT_STATUS_LABELS, components?.[row.key]?.status) }}
              </span>
              <span class="system-page__component-note">{{ row.note }}</span>
            </li>
          </ul>
        </section>

        <section class="system-page__card" data-testid="queues-card">
          <h3 class="system-page__card-title">操作任务队列</h3>
          <div class="system-page__queue-summary">
            <button
              v-for="item of [
                ['queued', '已排队'],
                ['running', '执行中'],
                ['waiting_device', '等待设备'],
                ['verification_required', '结果待核验'],
              ]"
              :key="item[0]"
              type="button"
              class="system-page__queue-item"
              :data-testid="`queue-${item[0]}`"
              @click="goOperations(item[0])"
            >
              <span class="system-page__queue-count">
                {{ status.queues.operation_tasks[item[0]] ?? 0 }}
              </span>
              <span class="system-page__queue-label">{{ item[1] }}</span>
            </button>
          </div>
          <p v-if="status.queues.oldest_queued_age_seconds !== null" class="system-page__note">
            最老排队任务已等待 {{ formatDuration(status.queues.oldest_queued_age_seconds) }}
          </p>
        </section>

        <section class="system-page__card" data-testid="collection-card">
          <h3 class="system-page__card-title">采集（最近 24 小时）</h3>
          <div class="system-page__collection-outcomes">
            <span class="system-page__collection-item system-page__collection-item--ok">
              成功 {{ status.collection.last_24h.succeeded }}
            </span>
            <span class="system-page__collection-item system-page__collection-item--partial">
              部分成功 {{ status.collection.last_24h.partial }}
            </span>
            <span class="system-page__collection-item system-page__collection-item--failed">
              失败 {{ status.collection.last_24h.failed }}
            </span>
          </div>
          <table
            v-if="status.collection.current_failures.length > 0"
            class="system-page__failure-table"
            data-testid="current-failures"
          >
            <thead>
              <tr>
                <th>设备</th>
                <th>错误码</th>
                <th>最近失败时间</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="failure in status.collection.current_failures" :key="`${failure.device_id}-${failure.collection_type}`">
                <td>{{ failureText(failure) }}</td>
                <td><code>{{ failure.error_code ?? '—' }}</code></td>
                <td>{{ formatDateTime(failure.failed_at) }}</td>
              </tr>
            </tbody>
          </table>
          <p v-else class="system-page__note">最近 24 小时无采集失败记录</p>
        </section>

        <section class="system-page__card" data-testid="verification-card">
          <h3 class="system-page__card-title">结果待核验任务</h3>
          <p class="system-page__note">
            <span data-testid="verification-count">{{ status.verification_required.count }}</span>
            个任务等待核验
            <template v-if="status.verification_required.oldest_at">
              ，最早自 {{ formatDateTime(status.verification_required.oldest_at) }}
            </template>
          </p>
          <el-link
            v-if="status.verification_required.count > 0"
            type="primary"
            data-testid="verification-link"
            @click="goOperations('verification_required')"
          >
            查看待核验任务
          </el-link>
        </section>
      </template>
    </AsyncState>
  </div>
</template>

<style scoped>
.system-page__meta {
  display: flex;
  gap: 16px;
  align-items: center;
  margin-bottom: 12px;
  color: var(--warden-status-unknown);
  font-size: 12px;
}
.system-page__maintenance {
  margin-bottom: 12px;
}
.system-page__card {
  background: var(--el-bg-color);
  border: 1px solid var(--el-border-color-light);
  border-radius: 6px;
  padding: 14px 16px;
  margin-bottom: 12px;
}
.system-page__card-title {
  margin: 0 0 10px;
  font-size: 14px;
  font-weight: 600;
}
.system-page__component-list {
  list-style: none;
  margin: 0;
  padding: 0;
}
.system-page__component-row {
  display: flex;
  gap: 12px;
  align-items: baseline;
  padding: 8px 0;
  border-bottom: 1px solid var(--el-border-color-lighter);
  font-size: 13px;
}
.system-page__component-row:last-child {
  border-bottom: none;
}
.system-page__component-name {
  width: 110px;
  flex-shrink: 0;
}
.system-page__status {
  width: 64px;
  flex-shrink: 0;
  font-weight: 600;
}
.system-page__status--ok {
  color: var(--warden-status-healthy);
}
.system-page__status--degraded {
  color: var(--warden-status-warning);
}
.system-page__status--stopped,
.system-page__status--unavailable {
  color: var(--warden-status-critical);
}
.system-page__component-note {
  color: var(--warden-status-unknown);
  word-break: break-all;
}
.system-page__queue-summary {
  display: flex;
  gap: 16px;
}
.system-page__queue-item {
  border: none;
  background: transparent;
  cursor: pointer;
  text-align: left;
  padding: 4px 0;
}
.system-page__queue-item:hover .system-page__queue-label {
  text-decoration: underline;
}
.system-page__queue-count {
  display: block;
  font-size: 22px;
  font-weight: 700;
}
.system-page__queue-label {
  color: var(--warden-status-unknown);
  font-size: 12px;
}
.system-page__collection-outcomes {
  display: flex;
  gap: 20px;
  margin-bottom: 10px;
}
.system-page__collection-item--ok {
  color: var(--warden-status-healthy);
}
.system-page__collection-item--partial {
  color: var(--warden-status-warning);
}
.system-page__collection-item--failed {
  color: var(--warden-status-critical);
}
.system-page__failure-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
.system-page__failure-table th,
.system-page__failure-table td {
  text-align: left;
  padding: 6px 8px;
  border-bottom: 1px solid var(--el-border-color-lighter);
}
.system-page__note {
  margin: 6px 0;
  font-size: 13px;
}
</style>
