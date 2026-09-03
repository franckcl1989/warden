<script setup lang="ts">
import { ElButton, ElTable, ElTableColumn } from 'element-plus';
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';

import AsyncState from '@/components/AsyncState.vue';
import OperationState from '@/components/OperationState.vue';
import OperationLaunchDialog from '@/features/operations/OperationLaunchDialog.vue';
import type { ApiError } from '@/api/client';
import { request } from '@/api/client';
import type {
  CapabilityView,
  OperationTaskDetail,
  OperationsListResponse,
} from '@/api/types';
import { REQUIREMENTS } from '@/api/generated/contracts';
import { registerCacheEntry } from '@/lib/query-cache';
import { formatDateTime } from '@/lib/format';
import { useAuthStore } from '@/stores/auth';
import { listQueryString } from './common';

// 群晖 NAS「任务与日志」页签的备份/快照任务状态视图（NAS-ACT-05，
// PRODUCT_DESIGN §5.3）：只读取持久化的最近一次 backup.status.refresh
// 任务结果（M4T3 决策：清单证据持久化在 operation_tasks.evidence，无独立表）。
// - 无刷新任务：显示"尚未刷新"空态 + 刷新入口（权限与能力支持时）；
// - 最近一次刷新成功：渲染任务证据中的备份任务（jobs）与功能包（packages）清单，
//   数据时间取任务证据记录的时刻，不做任何前端猜测；
// - 最近一次刷新未成功/未完成：如实显示任务状态与错误，不渲染任何清单内容；
// - 证据结构无法解析时提示查看任务详情，绝不伪造空"正常"。
const props = defineProps<{
  deviceId: string;
  deviceName: string;
  capabilities: CapabilityView[];
}>();

const auth = useAuthStore();
const router = useRouter();

const state = ref<'loading' | 'ready' | 'error' | 'permission_denied'>('loading');
const error = ref<ApiError | null>(null);
const latest = ref<OperationTaskDetail | null>(null);
const refreshDialogVisible = ref(false);

const requirementId = 'NAS-ACT-05';
const capabilityKey = 'backup.status.refresh';

const backupCapability = computed(() =>
  props.capabilities.find((row) => row.capability_key === capabilityKey),
);

const canExecute = (): boolean =>
  auth.permissions.some((permission) => permission.startsWith('operation.execute.'));

const refreshSupported = computed(
  () => backupCapability.value?.support_state === 'supported',
);

const refreshDeniedReason = computed(() => {
  const capability = backupCapability.value;
  if (capability === undefined) {
    return '尚无该能力发现记录，请先执行连接测试';
  }
  const reasonParts = [capability.reason_code, capability.detail].filter(
    (part): part is string => part !== null && part !== undefined && part !== '',
  );
  if (capability.support_state === 'not_configured') {
    return `未配置：${reasonParts.join('；') || '缺少必要配置'}`;
  }
  if (capability.support_state === 'unsupported') {
    return `设备不支持：${reasonParts.join('；') || '无附加原因'}`;
  }
  return '';
});

const refreshingStates = new Set(['queued', 'running', 'waiting_device']);
const refreshBusy = computed(() => {
  const task = latest.value;
  return task !== null && refreshingStates.has(task.state);
});

async function load(silent = false): Promise<void> {
  if (!silent) {
    state.value = 'loading';
  }
  error.value = null;
  try {
    const query = listQueryString({
      page: 1,
      page_size: 1,
      device_id: props.deviceId,
      capability_key: capabilityKey,
    });
    const list = await request<OperationsListResponse>(`/operations?${query}`);
    const first = list.items[0];
    if (first === undefined) {
      latest.value = null;
      state.value = 'ready';
      return;
    }
    latest.value = await request<OperationTaskDetail>(`/operations/${first.id}`);
    state.value = 'ready';
  } catch (caught) {
    error.value = caught as ApiError;
    state.value = error.value.code === 'permission_denied' ? 'permission_denied' : 'error';
  }
}

function onRefreshCreated(taskId: string): void {
  // 与其余操作流程一致（UI_SPEC §8）：提交后立即进入任务详情，SSE 实时更新
  void router.push({ name: 'operations-detail', params: { id: taskId } });
}

// SSE operation.updated / 轮询降级到达时静默重取最近一次刷新任务
let unregisterCache: (() => void) | null = null;

onMounted(() => {
  void load();
  unregisterCache = registerCacheEntry({
    kind: 'operations',
    id: props.deviceId,
    refetch: () => void load(true),
  });
});

onBeforeUnmount(() => {
  unregisterCache?.();
  unregisterCache = null;
});

// ---------- 证据解析（只读持久化任务结果，结构校验失败时如实提示） ----------

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

interface BackupJobRow {
  name: string;
  type: string;
  status: string;
  lastRunAt: string | null;
}

interface BackupPackageRow {
  name: string;
  package: string;
  available: boolean;
  reason: string | null;
}

interface ParsedInventory {
  jobs: BackupJobRow[];
  packages: BackupPackageRow[];
  observedAt: string | null;
  /** 任务证据不存在或没有 execution 清单结构（区别于"设备报告清单为空"）。 */
  missing: boolean;
  /** 任务证据存在但结构无法解析。 */
  unparsable: boolean;
}

const EMPTY_INVENTORY: ParsedInventory = {
  jobs: [],
  packages: [],
  observedAt: null,
  missing: false,
  unparsable: false,
};

function parseInventory(): ParsedInventory {
  const evidence = latest.value?.evidence;
  if (!isRecord(evidence)) {
    return { ...EMPTY_INVENTORY, missing: true };
  }
  const execution = evidence['execution'];
  if (!isRecord(execution)) {
    return { ...EMPTY_INVENTORY, missing: true };
  }
  const jobsRaw = execution['jobs'];
  const packagesRaw = execution['packages'];
  if (jobsRaw === undefined && packagesRaw === undefined) {
    return { ...EMPTY_INVENTORY, missing: true };
  }
  const observedAtValue = execution['observed_at'];
  const observedAt = typeof observedAtValue === 'string' ? observedAtValue : null;

  const jobs: BackupJobRow[] = [];
  const packages: BackupPackageRow[] = [];
  let unparsable = false;
  if (Array.isArray(jobsRaw)) {
    for (const row of jobsRaw) {
      if (!isRecord(row)) {
        unparsable = true;
        continue;
      }
      const { name, type, status } = row;
      const lastRunAt = row['last_run_at'];
      if (
        typeof name !== 'string' ||
        typeof type !== 'string' ||
        typeof status !== 'string' ||
        (lastRunAt !== null && typeof lastRunAt !== 'string')
      ) {
        unparsable = true;
        continue;
      }
      jobs.push({ name, type, status, lastRunAt });
    }
  } else if (jobsRaw !== undefined) {
    unparsable = true;
  }
  if (Array.isArray(packagesRaw)) {
    for (const row of packagesRaw) {
      if (!isRecord(row)) {
        unparsable = true;
        continue;
      }
      const { name, package: packageId, available, reason } = row;
      if (
        typeof name !== 'string' ||
        typeof packageId !== 'string' ||
        typeof available !== 'boolean' ||
        (reason !== null && reason !== undefined && typeof reason !== 'string')
      ) {
        unparsable = true;
        continue;
      }
      packages.push({
        name,
        package: packageId,
        available,
        reason: typeof reason === 'string' ? reason : null,
      });
    }
  } else if (packagesRaw !== undefined) {
    unparsable = true;
  }
  return { jobs, packages, observedAt, missing: false, unparsable };
}

const inventory = computed<ParsedInventory>(() => {
  if (latest.value === null || latest.value.state !== 'succeeded') {
    return EMPTY_INVENTORY;
  }
  return parseInventory();
});

function taskLink(task: OperationTaskDetail): void {
  void router.push({ name: 'operations-detail', params: { id: task.id } });
}

function showRefreshFlow(): void {
  if (!canExecute() || !refreshSupported.value || refreshBusy.value) {
    return;
  }
  refreshDialogVisible.value = true;
}
</script>

<template>
  <div class="backup-status" data-testid="backup-status-panel">
    <div class="backup-status__header">
      <h3 class="backup-status__title">
        <span class="backup-status__requirement">{{ requirementId }}</span>
        快照与备份任务状态（{{ REQUIREMENTS[requirementId]?.title ?? '' }}）
      </h3>
      <div class="backup-status__actions">
        <el-button
          v-if="canExecute() && refreshSupported"
          size="small"
          :disabled="refreshBusy"
          data-testid="backup-refresh-button"
          @click="showRefreshFlow"
        >
          {{ refreshBusy ? '刷新中…' : '刷新备份状态' }}
        </el-button>
        <el-button
          v-else-if="canExecute() && !refreshSupported"
          size="small"
          disabled
          data-testid="backup-refresh-button"
        >
          刷新备份状态
        </el-button>
      </div>
    </div>
    <p
      v-if="!refreshSupported"
      class="backup-status__deny"
      data-testid="backup-refresh-denied"
    >
      {{ refreshDeniedReason }}
    </p>

    <AsyncState :state="state" :error="error" @retry="load">
      <template v-if="latest === null">
        <p class="backup-status__empty" data-testid="backup-status-empty">
          尚未刷新备份/快照任务状态：NAS-ACT-05 刷新会读取设备备份任务与功能包状态，
          结果保存在最近一次刷新任务中，此处不展示任何推测数据。
        </p>
      </template>

      <template v-else-if="latest.state === 'succeeded'">
        <template v-if="!inventory.unparsable && !inventory.missing">
          <p class="backup-status__meta">
            最近刷新：
            <button
              class="backup-status__task-link"
              type="button"
              data-testid="backup-task-link"
              @click="taskLink(latest)"
            >
              任务 {{ latest.id }}
            </button>
            <template v-if="inventory.observedAt">
              · 设备清单读取于 {{ formatDateTime(inventory.observedAt) }}
            </template>
            <template v-else> · 完成于 {{ formatDateTime(latest.finished_at) }}</template>
          </p>

          <h4 class="backup-status__subtitle">备份任务</h4>
          <el-table
            v-if="inventory.jobs.length > 0"
            :data="inventory.jobs"
            class="backup-status__table"
            data-testid="backup-jobs-table"
          >
            <el-table-column prop="name" label="任务名" min-width="180" />
            <el-table-column prop="type" label="类型" width="140" />
            <el-table-column prop="status" label="状态" width="120" />
            <el-table-column label="最近运行" width="160">
              <template #default="{ row }">
                {{ formatDateTime((row as BackupJobRow).lastRunAt) }}
              </template>
            </el-table-column>
          </el-table>
          <p v-else class="backup-status__note">设备报告暂无备份任务</p>

          <h4 class="backup-status__subtitle">功能包</h4>
          <el-table
            v-if="inventory.packages.length > 0"
            :data="inventory.packages"
            class="backup-status__table"
            data-testid="backup-packages-table"
          >
            <el-table-column prop="name" label="名称" min-width="180" />
            <el-table-column prop="package" label="包标识" width="160" />
            <el-table-column label="可用性" width="200">
              <template #default="{ row }">
                <template v-if="(row as BackupPackageRow).available">可用</template>
                <template v-else>
                  不可用<span v-if="(row as BackupPackageRow).reason">
                    （{{ (row as BackupPackageRow).reason }}）
                  </span>
                </template>
              </template>
            </el-table-column>
          </el-table>
          <p v-else class="backup-status__note">设备报告暂无备份功能包信息</p>
        </template>
        <template v-else-if="inventory.missing">
          <p class="backup-status__note" data-testid="backup-evidence-missing">
            刷新任务成功，但任务证据未包含备份清单；请打开任务详情查看原始结果。
          </p>
        </template>
        <p v-else class="backup-status__note" data-testid="backup-evidence-unparsable">
          刷新任务成功，但其证据结构无法解析为清单；请打开任务详情查看原始结果。
        </p>
      </template>

      <template v-else>
        <p class="backup-status__state-note" data-testid="backup-task-not-succeeded">
          最近一次刷新任务状态：
          <OperationState :state="latest.state" />
          <span v-if="latest.error_detail" class="backup-status__error">
            （{{ latest.error_detail }}）
          </span>
          <button
            class="backup-status__task-link"
            type="button"
            data-testid="backup-task-link"
            @click="taskLink(latest)"
          >
            查看任务详情
          </button>
        </p>
      </template>
    </AsyncState>

    <OperationLaunchDialog
      v-model="refreshDialogVisible"
      :device="{ id: deviceId, name: deviceName }"
      :capability-key="capabilityKey"
      :requirement-id="requirementId"
      @created="onRefreshCreated"
    />
  </div>
</template>

<style scoped>
.backup-status {
  margin-bottom: 22px;
}
.backup-status__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 10px;
}
.backup-status__title {
  margin: 0;
  font-size: 15px;
}
.backup-status__requirement {
  font-family: monospace;
  color: var(--warden-status-unknown);
  margin-right: 10px;
  font-size: 12px;
}
.backup-status__meta {
  color: var(--warden-status-unknown);
  font-size: 12px;
  margin: 4px 0 10px;
}
.backup-status__task-link {
  border: none;
  background: none;
  padding: 0;
  color: var(--el-color-primary);
  font-size: inherit;
  font-family: monospace;
  cursor: pointer;
  text-decoration: underline;
}
.backup-status__subtitle {
  margin: 12px 0 6px;
  font-size: 13px;
}
.backup-status__table {
  width: 100%;
}
.backup-status__note,
.backup-status__empty,
.backup-status__state-note {
  color: var(--warden-status-unknown);
  font-size: 13px;
  margin: 6px 0;
}
.backup-status__deny {
  color: var(--warden-status-warning);
  font-size: 12px;
  margin: 0 0 8px;
}
.backup-status__state-note {
  display: flex;
  align-items: center;
  gap: 8px;
}
.backup-status__error {
  color: var(--warden-status-critical);
}
</style>
