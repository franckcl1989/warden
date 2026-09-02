<script setup lang="ts">
import {
  ElButton,
  ElDialog,
  ElInput,
  ElOption,
  ElSelect,
  ElTable,
  ElTableColumn,
} from 'element-plus';
import { onMounted, ref } from 'vue';

import AsyncState from '@/components/AsyncState.vue';
import PaginationBar from '@/components/PaginationBar.vue';
import type { ApiError } from '@/api/client';
import { request } from '@/api/client';
import type {
  AuditLogDetailItem,
  AuditLogListItem,
  AuditLogListResponse,
  DeviceListResponse,
  UserListResponse,
} from '@/api/types';
import { formatDateTime } from '@/lib/format';

// 审计页（PLT-07，管理员）：筛选（操作者/动作前缀/资源/设备/时间段）+
// 详情对话框展示脱敏 detail_jsonb。只读，无删除/导出。
const state = ref<'loading' | 'ready' | 'empty' | 'error' | 'permission_denied'>('loading');
const error = ref<ApiError | null>(null);
const response = ref<AuditLogListResponse | null>(null);

const actorOptions = ref<{ id: string; username: string }[]>([]);
const deviceOptions = ref<{ id: string; name: string }[]>([]);
const actorFilter = ref<string | null>(null);
const actionFilter = ref<string>('');
const resourceTypeFilter = ref<string | null>(null);
const deviceFilter = ref<string>('');
const fromFilter = ref('');
const toFilter = ref('');
const page = ref(1);
const pageSize = ref(20);

const RESOURCE_OPTIONS = ['device', 'user', 'session', 'operation', 'file', 'audit', 'system'];

const detailOpen = ref(false);
const detailState = ref<'loading' | 'ready' | 'error' | 'permission_denied' | 'not_found'>(
  'loading',
);
const detailError = ref<ApiError | null>(null);
const detail = ref<AuditLogDetailItem | null>(null);

function applyFilters(): void {
  page.value = 1;
  void load();
}

function clearFilters(): void {
  actorFilter.value = null;
  actionFilter.value = '';
  resourceTypeFilter.value = null;
  deviceFilter.value = '';
  fromFilter.value = '';
  toFilter.value = '';
  page.value = 1;
  void load();
}

async function load(): Promise<void> {
  state.value = 'loading';
  error.value = null;
  try {
    const params = new URLSearchParams({
      page: String(page.value),
      page_size: String(pageSize.value),
    });
    if (actorFilter.value) params.set('actor_user_id', actorFilter.value);
    if (actionFilter.value.trim()) params.set('action', actionFilter.value.trim());
    if (resourceTypeFilter.value) params.set('resource_type', resourceTypeFilter.value);
    if (deviceFilter.value.trim()) params.set('device_id', deviceFilter.value.trim());
    if (fromFilter.value) params.set('from', new Date(fromFilter.value).toISOString());
    if (toFilter.value) params.set('to', new Date(toFilter.value).toISOString());
    const result = await request<AuditLogListResponse>(`/audit-logs?${params}`);
    response.value = result;
    state.value = result.total === 0 ? 'empty' : 'ready';
  } catch (caught) {
    error.value = caught as ApiError;
    state.value = error.value.code === 'permission_denied' ? 'permission_denied' : 'error';
  }
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

async function openDetail(row: AuditLogListItem): Promise<void> {
  detailOpen.value = true;
  detailState.value = 'loading';
  detailError.value = null;
  detail.value = null;
  try {
    detail.value = await request<AuditLogDetailItem>(`/audit-logs/${row.id}`);
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

function detailJsonText(): string {
  const detailBody = detail.value?.detail;
  if (detailBody === undefined || detailBody === null) {
    return '';
  }
  return JSON.stringify(detailBody, null, 2);
}

function hasFilters(): boolean {
  return (
    actorFilter.value !== null ||
    actionFilter.value.trim() !== '' ||
    resourceTypeFilter.value !== null ||
    deviceFilter.value.trim() !== '' ||
    fromFilter.value !== '' ||
    toFilter.value !== ''
  );
}

function emptyText(): string {
  if (hasFilters()) {
    return '筛选无结果';
  }
  return '暂无审计记录';
}

async function loadOptions(): Promise<void> {
  try {
    const [users, devices] = await Promise.all([
      request<UserListResponse>('/users?page=1&page_size=100'),
      request<DeviceListResponse>('/devices?page=1&page_size=100'),
    ]);
    actorOptions.value = (users.items ?? []).map((user) => ({
      id: user.id,
      username: user.username,
    }));
    deviceOptions.value = (devices.items ?? []).map((device) => ({
      id: device.id,
      name: device.name,
    }));
  } catch {
    // 选项加载失败不阻塞审计列表本身
  }
}

onMounted(() => {
  void load();
  void loadOptions();
});
</script>

<template>
  <div class="audit-page" data-testid="audit-page">
    <div class="audit-page__toolbar">
      <el-select
        v-model="actorFilter"
        placeholder="操作者"
        clearable
        filterable
        class="audit-page__filter"
        data-testid="filter-actor"
        @change="applyFilters"
      >
        <el-option
          v-for="actor in actorOptions"
          :key="actor.id"
          :value="actor.id"
          :label="actor.username"
        />
      </el-select>
      <el-input
        v-model="actionFilter"
        placeholder="动作前缀，如 device."
        clearable
        class="audit-page__filter"
        data-testid="filter-action"
        @keyup.enter="applyFilters"
        @clear="applyFilters"
      />
      <el-select
        v-model="resourceTypeFilter"
        placeholder="资源类型"
        clearable
        class="audit-page__filter"
        data-testid="filter-resource"
        @change="applyFilters"
      >
        <el-option
          v-for="resource in RESOURCE_OPTIONS"
          :key="resource"
          :value="resource"
          :label="resource"
        />
      </el-select>
      <el-select
        v-model="deviceFilter"
        placeholder="设备"
        clearable
        filterable
        class="audit-page__filter"
        data-testid="filter-device"
        @change="applyFilters"
      >
        <el-option
          v-for="device in deviceOptions"
          :key="device.id"
          :value="device.id"
          :label="device.name"
        />
      </el-select>
      <el-input
        v-model="fromFilter"
        type="datetime-local"
        class="audit-page__filter"
        data-testid="filter-from"
        @change="applyFilters"
      />
      <el-input
        v-model="toFilter"
        type="datetime-local"
        class="audit-page__filter"
        data-testid="filter-to"
        @change="applyFilters"
      />
      <el-button data-testid="filter-reset" @click="clearFilters">清除筛选</el-button>
    </div>

    <AsyncState :state="state" :error="error" :empty-text="emptyText()" @retry="load">
      <el-table
        v-if="(response?.items ?? []).length > 0"
        :data="(response?.items ?? []) as AuditLogListItem[]"
        row-key="id"
        data-testid="audit-table"
        @row-click="openDetail"
      >
        <el-table-column label="时间" width="150">
          <template #default="{ row }">{{ formatDateTime(row.occurred_at) }}</template>
        </el-table-column>
        <el-table-column label="操作者" width="110">
          <template #default="{ row }">{{ row.actor_username ?? '—' }}</template>
        </el-table-column>
        <el-table-column label="动作" min-width="170">
          <template #default="{ row }"
            ><code>{{ row.action }}</code></template
          >
        </el-table-column>
        <el-table-column label="资源" min-width="150">
          <template #default="{ row }">
            {{ row.resource_type ?? '—'
            }}<span v-if="row.resource_id"> / {{ row.resource_id }}</span>
          </template>
        </el-table-column>
        <el-table-column label="设备" width="90">
          <template #default="{ row }">{{ row.device_id ? '是' : '—' }}</template>
        </el-table-column>
        <el-table-column label="需求" width="90">
          <template #default="{ row }">{{ row.requirement_id ?? '—' }}</template>
        </el-table-column>
        <el-table-column label="结果" width="140">
          <template #default="{ row }">{{ row.result }}</template>
        </el-table-column>
        <el-table-column label="来源 IP" width="130">
          <template #default="{ row }">{{ row.source_ip ?? '—' }}</template>
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

    <el-dialog v-model="detailOpen" title="审计详情" width="720px">
      <AsyncState :state="detailState" :error="detailError">
        <template v-if="detail">
          <dl class="audit-page__detail">
            <div>
              <dt>动作</dt>
              <dd>
                <code>{{ detail.action }}</code>
              </dd>
            </div>
            <div>
              <dt>操作者</dt>
              <dd>{{ detail.actor_username ?? '—' }}</dd>
            </div>
            <div>
              <dt>时间</dt>
              <dd>{{ formatDateTime(detail.occurred_at) }}</dd>
            </div>
            <div>
              <dt>资源</dt>
              <dd>{{ detail.resource_type ?? '—' }} {{ detail.resource_id ?? '' }}</dd>
            </div>
            <div>
              <dt>设备</dt>
              <dd>{{ detail.device_id ?? '—' }}</dd>
            </div>
            <div>
              <dt>需求编号</dt>
              <dd>{{ detail.requirement_id ?? '—' }}</dd>
            </div>
            <div>
              <dt>任务</dt>
              <dd>{{ detail.task_id ?? '—' }}</dd>
            </div>
            <div>
              <dt>结果</dt>
              <dd>{{ detail.result }}</dd>
            </div>
            <div>
              <dt>请求 ID</dt>
              <dd>
                <code>{{ detail.request_id ?? '—' }}</code>
              </dd>
            </div>
            <div>
              <dt>会话</dt>
              <dd>{{ detail.session_id ?? '—' }}</dd>
            </div>
            <div>
              <dt>来源</dt>
              <dd>{{ detail.source_ip ?? '—' }} · {{ detail.user_agent_summary ?? '—' }}</dd>
            </div>
          </dl>
          <h4 class="audit-page__detail-sub">脱敏详情</h4>
          <pre
            v-if="detailJsonText() !== ''"
            class="audit-page__json"
            data-testid="audit-detail-json"
            >{{ detailJsonText() }}</pre>
          <p v-else class="audit-page__no-detail">无附加详情</p>
        </template>
      </AsyncState>
      <template #footer>
        <el-button @click="detailOpen = false">关闭</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.audit-page__toolbar {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 12px;
}
.audit-page__filter {
  width: 180px;
}
.audit-page__detail {
  margin: 0 0 16px;
}
.audit-page__detail div {
  display: flex;
  gap: 12px;
  padding: 6px 0;
  border-bottom: 1px solid var(--el-border-color-lighter);
  font-size: 13px;
}
.audit-page__detail dt {
  color: var(--warden-status-unknown);
  width: 90px;
  flex-shrink: 0;
}
.audit-page__detail dd {
  margin: 0;
  word-break: break-all;
}
.audit-page__detail-sub {
  margin: 0 0 8px;
  font-size: 14px;
}
.audit-page__json {
  max-height: 320px;
  overflow: auto;
  background: var(--el-fill-color-light);
  padding: 10px;
  border-radius: 4px;
  font-size: 12px;
}
.audit-page__no-detail {
  color: var(--warden-status-unknown);
}
</style>
