<script setup lang="ts">
import {
  ElButton,
  ElDialog,
  ElForm,
  ElFormItem,
  ElInput,
  ElMessage,
  ElOption,
  ElSelect,
  ElTag,
} from 'element-plus';
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue';
import { useRoute } from 'vue-router';

import AsyncState from '@/components/AsyncState.vue';
import ErrorDetail from '@/components/ErrorDetail.vue';
import OperationState from '@/components/OperationState.vue';
import OperationTimeline from '@/components/OperationTimeline.vue';
import type { ApiError } from '@/api/client';
import { request } from '@/api/client';
import type { OperationResolveRequest, OperationTaskDetail } from '@/api/types';
import { formatDateTime, formatDateTimeSeconds } from '@/lib/format';
import {
  OPERATION_RISK_LABELS,
  RESOLVE_EVIDENCE_LABELS,
  RESOLVE_OUTCOME_LABELS,
  label,
} from '@/lib/labels';
import { registerCacheEntry } from '@/lib/query-cache';
import { useAuthStore } from '@/stores/auth';

// 操作任务详情（PLT-05，UI_SPEC §8）：时间线、参数（脱敏后展示）、
// 结果/错误（稳定错误码 + 说明）、证据；verification_required 时管理员
// 可"重新回读"（operations_verify）或"人工核验"（resolve-verification）。
const route = useRoute();
const auth = useAuthStore();

const operationId = computed(() => String(route.params.id));

const state = ref<'loading' | 'ready' | 'error' | 'permission_denied' | 'not_found'>('loading');
const refreshing = ref(false);
const error = ref<ApiError | null>(null);
const detail = ref<OperationTaskDetail | null>(null);

const verifyBusy = ref(false);
const verifyError = ref<ApiError | null>(null);
const cancelBusy = ref(false);
const cancelError = ref<ApiError | null>(null);

async function load(silent = false): Promise<void> {
  if (silent) {
    refreshing.value = true;
  } else {
    state.value = 'loading';
  }
  error.value = null;
  try {
    detail.value = await request<OperationTaskDetail>(`/operations/${operationId.value}`);
    state.value = 'ready';
  } catch (caught) {
    error.value = caught as ApiError;
    if (error.value.code === 'permission_denied') {
      state.value = 'permission_denied';
    } else if (error.value.code === 'resource_not_found') {
      state.value = 'not_found';
    } else if (!silent) {
      state.value = 'error';
    }
  } finally {
    refreshing.value = false;
  }
}

let unregister: (() => void) | null = null;

onMounted(() => {
  void load();
  unregister = registerCacheEntry({
    kind: 'operation-detail',
    id: operationId.value,
    refetch: () => void load(true),
  });
});

onBeforeUnmount(() => {
  unregister?.();
});

const isAdmin = computed(() => auth.user?.role === 'admin');
const showActions = computed(
  () => detail.value?.state === 'verification_required' && isAdmin.value,
);

function canCancel(): boolean {
  const current = detail.value?.state;
  return current === 'queued' || current === 'running';
}

async function verifyReadback(): Promise<void> {
  verifyBusy.value = true;
  verifyError.value = null;
  try {
    detail.value = await request<OperationTaskDetail>(`/operations/${operationId.value}/verify`, {
      method: 'POST',
    });
    state.value = 'ready';
  } catch (caught) {
    verifyError.value = caught as ApiError;
  } finally {
    verifyBusy.value = false;
  }
}

async function cancelTask(): Promise<void> {
  cancelBusy.value = true;
  cancelError.value = null;
  try {
    await request<OperationTaskDetail>(`/operations/${operationId.value}/cancel`, {
      method: 'POST',
    });
    await load(true);
  } catch (caught) {
    cancelError.value = caught as ApiError;
    if (cancelError.value.code === 'device_busy' || cancelError.value.code === 'preview_stale') {
      // fence 后不可取消（API_CONTRACT §6.2）：如实展示并提示刷新
      await load(true);
    }
  } finally {
    cancelBusy.value = false;
  }
}

// ---------- 人工核验 ----------
const resolveVisible = ref(false);
const resolveBusy = ref(false);
const resolveError = ref<ApiError | null>(null);
const resolveForm = reactive<OperationResolveRequest>({
  outcome: 'succeeded',
  evidence_type: 'device_ui',
  reference: '',
  reason: '',
});

function openResolve(): void {
  resolveForm.outcome = 'succeeded';
  resolveForm.evidence_type = 'device_ui';
  resolveForm.reference = '';
  resolveForm.reason = '';
  resolveError.value = null;
  resolveVisible.value = true;
}

async function submitResolve(): Promise<void> {
  resolveBusy.value = true;
  resolveError.value = null;
  try {
    detail.value = await request<OperationTaskDetail>(
      `/operations/${operationId.value}/resolve-verification`,
      { method: 'POST', body: { ...resolveForm } },
    );
    resolveVisible.value = false;
    state.value = 'ready';
    ElMessage.success('核验结论已记录');
  } catch (caught) {
    resolveError.value = caught as ApiError;
  } finally {
    resolveBusy.value = false;
  }
}

function paramsText(): string {
  if (detail.value === null) {
    return '';
  }
  return JSON.stringify(detail.value.parameters ?? {}, null, 2);
}

function evidenceText(): string {
  if (detail.value === null || detail.value.evidence === null) {
    return '';
  }
  return JSON.stringify(detail.value.evidence, null, 2);
}

function verificationStateText(): string {
  return detail.value?.verification_state ?? '—';
}
</script>

<template>
  <div class="operation-detail" data-testid="operation-detail">
    <AsyncState :state="state" :error="error" @retry="load">
      <template v-if="detail">
        <p v-if="refreshing" class="operation-detail__refreshing">任务已更新，正在刷新…</p>

        <div class="operation-detail__head">
          <h2 class="operation-detail__title">{{ detail.requirement_id }}</h2>
          <OperationState :state="detail.state" />
          <el-tag v-if="detail.risk_level" size="small" type="info">
            {{ label(OPERATION_RISK_LABELS, detail.risk_level) }}
          </el-tag>
          <span class="operation-detail__capability">
            <code>{{ detail.capability_key }}</code>
          </span>
        </div>

        <dl class="operation-detail__meta">
          <div>
            <dt>设备</dt>
            <dd>{{ detail.device.name }}</dd>
          </div>
          <div>
            <dt>发起人</dt>
            <dd>{{ detail.requested_by.username }}</dd>
          </div>
          <div>
            <dt>进度</dt>
            <dd>{{ detail.progress_percent }}%</dd>
          </div>
          <div>
            <dt>当前步骤</dt>
            <dd>{{ detail.current_step ?? '—' }}</dd>
          </div>
          <div>
            <dt>创建时间</dt>
            <dd>{{ formatDateTimeSeconds(detail.created_at) }}</dd>
          </div>
          <div>
            <dt>开始时间</dt>
            <dd>{{ formatDateTimeSeconds(detail.started_at) }}</dd>
          </div>
          <div>
            <dt>结束时间</dt>
            <dd>{{ formatDateTimeSeconds(detail.finished_at) }}</dd>
          </div>
          <div v-if="detail.timeout_at">
            <dt>计划超时</dt>
            <dd>{{ formatDateTime(detail.timeout_at) }}</dd>
          </div>
          <div v-if="detail.verification_state">
            <dt>核验状态</dt>
            <dd>{{ verificationStateText() }}</dd>
          </div>
        </dl>

        <section class="operation-detail__section">
          <h3>执行时间线</h3>
          <OperationTimeline :events="detail.events" />
        </section>

        <section class="operation-detail__section">
          <h3>参数与验证信息</h3>
          <pre class="operation-detail__json">{{ paramsText() }}</pre>
          <p class="operation-detail__sub">
            幂等键 <code>{{ detail.idempotency_key }}</code>
            <span v-if="detail.adapter_version">
              · 适配器版本 <code>{{ detail.adapter_version }}</code></span
            >
            <span v-if="detail.conflict_scope">
              · 冲突范围 <code>{{ detail.conflict_scope }}</code></span
            >
          </p>
        </section>

        <section v-if="detail.error_code" class="operation-detail__section">
          <h3>错误</h3>
          <el-alert
            type="error"
            :closable="false"
            show-icon
            class="operation-detail__error"
            data-testid="operation-error"
          >
            <template #title>
              错误码：<code>{{ detail.error_code }}</code>
            </template>
            <p class="operation-detail__error-body">{{ detail.error_detail ?? '无附加说明' }}</p>
            <p class="operation-detail__sub">
              失败后不会自动重放；重试需重新创建预览与任务（API_CONTRACT §6.2）。
            </p>
          </el-alert>
        </section>

        <section class="operation-detail__section">
          <h3>结果摘要</h3>
          <p class="operation-detail__result">{{ detail.result_summary ?? '—' }}</p>
          <div v-if="evidenceText() !== ''" class="operation-detail__evidence">
            <h4>设备证据</h4>
            <pre class="operation-detail__json">{{ evidenceText() }}</pre>
          </div>
        </section>

        <section v-if="showActions" class="operation-detail__section" data-testid="verify-actions">
          <h3>结果核验</h3>
          <p class="operation-detail__sub">
            任务处于"结果待核验"：可触发适配器重新回读（只读，不会重放动作），或根据
            可复核外部证据人工标记核验结论。
          </p>
          <div class="operation-detail__actions">
            <el-button
              type="primary"
              plain
              :loading="verifyBusy"
              data-testid="verify-readback"
              @click="verifyReadback"
            >
              重新回读
            </el-button>
            <el-button type="primary" data-testid="open-resolve" @click="openResolve">
              人工核验
            </el-button>
            <el-button
              v-if="canCancel()"
              :loading="cancelBusy"
              data-testid="cancel-task"
              @click="cancelTask"
            >
              取消任务
            </el-button>
          </div>
          <ErrorDetail
            v-if="verifyError"
            :error="verifyError"
            class="operation-detail__error-block"
          />
          <ErrorDetail
            v-if="cancelError"
            :error="cancelError"
            class="operation-detail__error-block"
          />
        </section>
        <el-button
          v-else-if="canCancel()"
          :loading="cancelBusy"
          data-testid="cancel-task"
          @click="cancelTask"
        >
          取消任务
        </el-button>
      </template>
    </AsyncState>

    <el-dialog
      v-model="resolveVisible"
      title="人工核验"
      width="560px"
      :close-on-click-modal="false"
    >
      <p class="operation-detail__dialog-hint">
        仅口头判断不能标记核验结论；必须选择证据类型并填写引用与理由（API_CONTRACT §6.2）。
      </p>
      <ErrorDetail
        v-if="resolveError"
        :error="resolveError"
        class="operation-detail__error-block"
      />
      <el-form label-width="90px">
        <el-form-item label="结论">
          <el-select v-model="resolveForm.outcome" data-testid="resolve-outcome">
            <el-option
              v-for="[value, text] in Object.entries(RESOLVE_OUTCOME_LABELS)"
              :key="value"
              :value="value"
              :label="text"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="证据类型">
          <el-select v-model="resolveForm.evidence_type" data-testid="resolve-evidence-type">
            <el-option
              v-for="[value, text] in Object.entries(RESOLVE_EVIDENCE_LABELS)"
              :key="value"
              :value="value"
              :label="text"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="证据引用">
          <el-input
            v-model="resolveForm.reference"
            placeholder="外部证据的定位信息（如设备界面截图位置/日志任务编号），必填且不超过 300 字"
            data-testid="resolve-reference"
          />
        </el-form-item>
        <el-form-item label="核验理由">
          <el-input
            v-model="resolveForm.reason"
            type="textarea"
            :rows="3"
            placeholder="说明为何判定该结论，必填且不超过 500 字"
            data-testid="resolve-reason"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="resolveVisible = false">取消</el-button>
        <el-button
          type="primary"
          :disabled="resolveForm.reference.trim() === '' || resolveForm.reason.trim() === ''"
          :loading="resolveBusy"
          data-testid="resolve-submit"
          @click="submitResolve"
        >
          记录核验结论
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.operation-detail__refreshing {
  color: var(--warden-status-running);
  font-size: 12px;
  margin: 0 0 8px;
}
.operation-detail__head {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 12px;
}
.operation-detail__title {
  margin: 0;
  font-size: 18px;
  font-family: monospace;
}
.operation-detail__capability {
  color: var(--warden-status-unknown);
}
.operation-detail__meta {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
  gap: 6px 20px;
  margin: 0 0 18px;
  font-size: 13px;
}
.operation-detail__meta div {
  display: flex;
  gap: 10px;
}
.operation-detail__meta dt {
  color: var(--warden-status-unknown);
  width: 80px;
  flex-shrink: 0;
}
.operation-detail__meta dd {
  margin: 0;
}
.operation-detail__section {
  margin-bottom: 22px;
}
.operation-detail__section h3 {
  margin: 0 0 10px;
  font-size: 15px;
}
.operation-detail__json {
  max-height: 300px;
  overflow: auto;
  background: var(--el-fill-color-light);
  border-radius: 4px;
  padding: 10px;
  font-size: 12px;
  margin: 0;
}
.operation-detail__sub {
  color: var(--warden-status-unknown);
  font-size: 12px;
}
.operation-detail__result {
  font-size: 14px;
}
.operation-detail__evidence h4 {
  margin: 12px 0 6px;
  font-size: 13px;
}
.operation-detail__error {
  margin-bottom: 8px;
}
.operation-detail__error-body {
  margin: 4px 0;
}
.operation-detail__error-block {
  margin-top: 10px;
}
.operation-detail__actions {
  display: flex;
  gap: 8px;
}
.operation-detail__dialog-hint {
  color: var(--warden-status-unknown);
  font-size: 12px;
  margin: 0 0 10px;
}
</style>
