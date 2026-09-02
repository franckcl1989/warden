<script setup lang="ts">
import { ElButton, ElDialog, ElForm, ElFormItem, ElInput, ElTag } from 'element-plus';
import { computed, onMounted, ref, watch } from 'vue';

import ErrorDetail from '@/components/ErrorDetail.vue';
import { isApiError, request, type ApiError } from '@/api/client';
import type { OperationPreviewResponse, OperationTaskView } from '@/api/types';
import { formatDateTime } from '@/lib/format';
import { OPERATION_RISK_LABELS, label } from '@/lib/labels';
import { useAuthStore } from '@/stores/auth';

// 操作发起流程（PLT-05，UI_SPEC §8）：
// 参数（JSON）→ POST /devices/{id}/operation-previews → 预览确认 →
// 设备名精确匹配 → POST /devices/{id}/operations（携带每次提交新生成的
// Idempotency-Key）→ 202 → 跳转任务详情。
// 高风险（risk_level=high）在预览/提交时若服务端判定最近 5 分钟未复验密码，
// 返回 401 reauthentication_required → 弹出复验 → 自动重试。
const props = defineProps<{
  modelValue: boolean;
  device: { id: string; name: string };
  capabilityKey: string;
  requirementId: string;
}>();

const emit = defineEmits<{
  'update:modelValue': [visible: boolean];
  created: [taskId: string];
}>();

const auth = useAuthStore();

type Phase = 'params' | 'previewing' | 'preview' | 'submitting' | 'reauth' | 'error';

const phase = ref<Phase>('params');
const flowError = ref<ApiError | null>(null);
const preview = ref<OperationPreviewResponse | null>(null);
const confirmationText = ref('');
const paramsJson = ref('{}');
const paramsError = ref<string | null>(null);
const reauthPassword = ref('');
const reauthBusy = ref(false);
const reauthError = ref<ApiError | null>(null);

const expectedName = computed(() => preview.value?.confirmation.expected ?? '');
const nameMatched = computed(
  () => confirmationText.value === expectedName.value && expectedName.value !== '',
);
const previewExpired = computed(() => {
  if (preview.value === null) {
    return false;
  }
  return new Date(preview.value.expires_at).getTime() <= Date.now();
});

watch(
  () => props.modelValue,
  (visible) => {
    if (visible) {
      resetFlow();
    }
  },
);

function resetFlow(): void {
  phase.value = 'params';
  flowError.value = null;
  preview.value = null;
  confirmationText.value = '';
  paramsJson.value = '{}';
  paramsError.value = null;
  reauthPassword.value = '';
  reauthError.value = null;
}

function closeDialog(): void {
  emit('update:modelValue', false);
}

function parseParamsJson(): Record<string, unknown> {
  paramsError.value = null;
  try {
    const parsed: unknown = JSON.parse(paramsJson.value === '' ? '{}' : paramsJson.value);
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      paramsError.value = '参数必须是 JSON 对象，例如 {"interface_id":"GigabitEthernet0/0/12"}';
      return {};
    }
    return parsed as Record<string, unknown>;
  } catch {
    paramsError.value = '参数 JSON 格式不正确，请检查括号与引号';
    return {};
  }
}

async function createPreview(): Promise<void> {
  const parameters = parseParamsJson();
  if (paramsError.value !== null) {
    phase.value = 'params';
    return;
  }
  phase.value = 'previewing';
  flowError.value = null;
  preview.value = null;
  try {
    const result = await request<OperationPreviewResponse>(
      `/devices/${props.device.id}/operation-previews`,
      {
        method: 'POST',
        body: { capability_key: props.capabilityKey, parameters },
      },
    );
    preview.value = result;
    phase.value = 'preview';
  } catch (caught) {
    if (isApiError(caught) && caught.code === 'reauthentication_required') {
      phase.value = 'reauth';
      return;
    }
    flowError.value = caught as ApiError;
    phase.value = 'error';
  }
}

async function confirmReauth(): Promise<void> {
  reauthBusy.value = true;
  reauthError.value = null;
  try {
    await auth.reauthenticate(reauthPassword.value);
    reauthPassword.value = '';
    if (preview.value === null) {
      await createPreview();
    } else {
      await submitOperation();
    }
  } catch (caught) {
    reauthError.value = caught as ApiError;
  } finally {
    reauthBusy.value = false;
  }
}

/** 预览失效：清空失效预览回到"可重新生成"状态，绝不让确认按钮再次提交失效令牌。 */
function discardPreview(error: ApiError | null): void {
  preview.value = null;
  confirmationText.value = '';
  flowError.value = error;
  phase.value = 'error';
}

async function submitOperation(): Promise<void> {
  if (preview.value === null || !nameMatched.value) {
    return;
  }
  if (previewExpired.value) {
    discardPreview(null);
    return;
  }
  phase.value = 'submitting';
  flowError.value = null;
  // 每次提交生成新的幂等键（crypto.randomUUID）；失败重试会重新生成，
  // 服务端按幂等键去重（API_CONTRACT §6.1）
  const idempotencyKey = crypto.randomUUID();
  try {
    const task = await request<OperationTaskView>(`/devices/${props.device.id}/operations`, {
      method: 'POST',
      headers: { 'Idempotency-Key': idempotencyKey },
      body: {
        preview_token: preview.value.preview_token,
        confirmation_text: confirmationText.value,
      },
    });
    closeDialog();
    emit('created', task.id);
  } catch (caught) {
    const error = caught as ApiError;
    if (error.code === 'reauthentication_required') {
      phase.value = 'reauth';
      return;
    }
    if (error.code === 'preview_stale') {
      // 令牌过期/参数变化：清空失效预览，用户从错误页直接重新生成（单次使用令牌已被消费）
      discardPreview(error);
      return;
    }
    flowError.value = error;
    phase.value = 'error';
  }
}

/** 错误页"重新生成预览"：保留已填参数，立即发起新预览。 */
function regeneratePreview(): void {
  preview.value = null;
  confirmationText.value = '';
  flowError.value = null;
  void createPreview();
}

function editParamsAfterError(): void {
  flowError.value = null;
  phase.value = 'params';
}

/** 预览仍有效但提交失败（如瞬时网络错误）：回到预览页让用户重新确认。 */
function retryAfterError(): void {
  if (preview.value !== null) {
    phase.value = 'preview';
  }
}

function paramEntries(): [string, unknown][] {
  if (preview.value === null) {
    return [];
  }
  return Object.entries(preview.value.normalized_parameters);
}

function paramsHaveValues(): boolean {
  return paramEntries().length > 0;
}

onMounted(() => {
  resetFlow();
});
</script>

<template>
  <el-dialog
    :model-value="modelValue"
    :title="`发起操作：${capabilityKey}`"
    width="620px"
    :close-on-click-modal="false"
    @update:model-value="emit('update:modelValue', $event)"
  >
    <div class="operation-flow">
      <p class="operation-flow__requirement" data-testid="flow-requirement">
        需求编号：{{ requirementId }}
      </p>

      <template v-if="phase === 'params'">
        <el-form label-width="90px">
          <el-form-item label="参数 JSON">
            <el-input
              v-model="paramsJson"
              type="textarea"
              :rows="4"
              data-testid="params-json-input"
              placeholder='{"interface_id":"GigabitEthernet0/0/12","enabled":false} 或 {}'
            />
          </el-form-item>
        </el-form>
        <p v-if="paramsError" class="operation-flow__error" data-testid="params-json-error">
          {{ paramsError }}
        </p>
        <p class="operation-flow__hint">
          参数必须符合该能力在 contracts/operations.json 中定义的参数模型；不填则使用空参数。
          预览前不会连接设备，服务端将做完整校验。
        </p>
      </template>

      <template v-if="phase === 'previewing' || phase === 'submitting'">
        <p class="operation-flow__busy" data-testid="flow-busy">
          {{ phase === 'previewing' ? '正在生成操作预览…' : '正在提交任务…' }}
        </p>
      </template>

      <template v-if="phase === 'preview' && preview">
        <div class="operation-flow__preview" data-testid="preview-panel">
          <div class="operation-flow__preview-row">
            <span class="operation-flow__label">目标设备</span>
            <span>{{ preview.target.name }}</span>
          </div>
          <div class="operation-flow__preview-row">
            <span class="operation-flow__label">风险等级</span>
            <el-tag
              :type="
                preview.risk_level === 'high'
                  ? 'danger'
                  : preview.risk_level === 'medium'
                    ? 'warning'
                    : 'info'
              "
              size="small"
            >
              {{ label(OPERATION_RISK_LABELS, preview.risk_level) }}
            </el-tag>
          </div>
          <div class="operation-flow__preview-row" data-testid="preview-impact">
            <span class="operation-flow__label">预期影响</span>
            <span>{{ preview.impact || '—' }}</span>
          </div>
          <div class="operation-flow__preview-row" data-testid="preview-params">
            <span class="operation-flow__label">参数</span>
            <span v-if="paramsHaveValues()" class="operation-flow__params">
              <code v-for="[key, value] in paramEntries()" :key="key">
                {{ key }} = {{ String(value) }}
              </code>
            </span>
            <span v-else>（无参数）</span>
          </div>
          <div class="operation-flow__preview-row">
            <span class="operation-flow__label">执行步骤</span>
            <ol class="operation-flow__steps" data-testid="preview-steps">
              <li v-for="step in preview.steps" :key="step">{{ step }}</li>
            </ol>
          </div>
          <div class="operation-flow__preview-row">
            <span class="operation-flow__label">令牌有效至</span>
            <span :class="{ 'operation-flow__expired': previewExpired }">
              {{ formatDateTime(preview.expires_at) }}
              <span v-if="previewExpired" class="operation-flow__expired-text"
                >（已过期，需重新生成）</span
              >
            </span>
          </div>
        </div>

        <el-form class="operation-flow__confirm" label-width="90px" @submit.prevent>
          <el-form-item label="设备名确认">
            <el-input
              v-model="confirmationText"
              data-testid="confirm-name-input"
              placeholder="输入目标设备名称以确认操作"
              autocomplete="off"
            />
          </el-form-item>
          <p class="operation-flow__hint">
            提交前请核对目标设备与影响；高风险操作已由服务端校验最近 5 分钟内完成密码复验。
          </p>
        </el-form>
      </template>

      <template v-if="phase === 'reauth'">
        <p class="operation-flow__hint" data-testid="reauth-hint">
          高风险操作需要重新验证当前用户密码（服务端会话复验有效期 5 分钟）。
        </p>
        <el-form label-width="90px" @submit.prevent>
          <el-form-item label="当前密码">
            <el-input
              v-model="reauthPassword"
              type="password"
              show-password
              autocomplete="current-password"
              data-testid="reauth-password-input"
            />
          </el-form-item>
        </el-form>
        <ErrorDetail v-if="reauthError" :error="reauthError" />
      </template>

      <template v-if="phase === 'error'">
        <p
          v-if="flowError === null || flowError.code === 'preview_stale'"
          class="operation-flow__expired-notice"
          data-testid="preview-expired-notice"
        >
          预览已过期，请重新生成预览。
        </p>
        <ErrorDetail v-if="flowError" :error="flowError" data-testid="flow-error" />
      </template>
    </div>

    <template #footer>
      <el-button @click="closeDialog">取消</el-button>
      <el-button
        v-if="phase === 'params'"
        type="primary"
        data-testid="preview-generate"
        @click="createPreview"
      >
        生成预览
      </el-button>
      <el-button
        v-if="phase === 'preview'"
        type="primary"
        :disabled="!nameMatched || previewExpired"
        data-testid="confirm-submit"
        @click="submitOperation"
      >
        确认并提交任务
      </el-button>
      <el-button
        v-if="phase === 'preview' && previewExpired"
        plain
        data-testid="regenerate-preview"
        @click="regeneratePreview"
      >
        重新生成预览
      </el-button>
      <el-button
        v-if="phase === 'reauth'"
        type="primary"
        :disabled="reauthPassword.trim() === '' || reauthBusy"
        data-testid="reauth-submit"
        @click="confirmReauth"
      >
        验证并继续
      </el-button>
      <template v-if="phase === 'error'">
        <el-button
          v-if="preview !== null"
          type="primary"
          data-testid="confirm-retry"
          @click="retryAfterError"
        >
          重新确认
        </el-button>
        <el-button v-else data-testid="edit-params-after-error" @click="editParamsAfterError">
          修改参数
        </el-button>
        <el-button
          v-if="preview === null"
          type="primary"
          data-testid="regenerate-preview"
          @click="regeneratePreview"
        >
          重新生成预览
        </el-button>
      </template>
    </template>
  </el-dialog>
</template>

<style scoped>
.operation-flow__requirement {
  margin: 0 0 10px;
  font-family: monospace;
  font-size: 12px;
  color: var(--warden-status-unknown);
}
.operation-flow__preview {
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 6px;
  padding: 4px 12px;
  margin-bottom: 12px;
}
.operation-flow__preview-row {
  display: flex;
  gap: 16px;
  padding: 8px 0;
  border-bottom: 1px solid var(--el-border-color-lighter);
  font-size: 13px;
}
.operation-flow__preview-row:last-child {
  border-bottom: none;
}
.operation-flow__label {
  width: 80px;
  flex-shrink: 0;
  color: var(--warden-status-unknown);
}
.operation-flow__params {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.operation-flow__params code {
  font-family: monospace;
  background: var(--el-fill-color-light);
  padding: 2px 6px;
  border-radius: 3px;
}
.operation-flow__steps {
  margin: 0;
  padding-left: 20px;
}
.operation-flow__expired-text {
  color: var(--warden-status-critical);
}
.operation-flow__expired-notice {
  color: var(--warden-status-critical);
  font-size: 13px;
  margin: 4px 0;
}
.operation-flow__error {
  color: var(--warden-status-critical);
  font-size: 13px;
}
.operation-flow__busy {
  color: var(--warden-status-unknown);
}
.operation-flow__hint {
  color: var(--warden-status-unknown);
  font-size: 12px;
  margin: 6px 0;
}
.operation-flow__confirm {
  margin-top: 4px;
}
</style>
