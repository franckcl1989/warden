<script setup lang="ts">
import { ElButton, ElDialog } from 'element-plus';
import { ref, watch } from 'vue';

import ErrorDetail from '@/components/ErrorDetail.vue';
import { isApiError, request, type ApiError } from '@/api/client';
import type { LaunchCreateResponse } from '@/api/types';

// KVM 控制台启动流程（M3T4 / PLT-09 launch 部分，API_CONTRACT.md §7）：
// 点击"打开控制台"→ 同步占位新标签页（避免弹窗拦截）→ POST
// /devices/{id}/launches → 成功后把新标签页导航到返回的一次性消费 URL
// （GET /launches/{id} 返回 HTML 自动跳转页，厂商 URL 不进入 SPA 状态，且
// 每次只可读取一次）。错误按稳定错误码渲染中文提示；其他错误走 ErrorDetail。
const props = defineProps<{
  modelValue: boolean;
  deviceId: string;
  capabilityKey: string;
  requirementId: string;
}>();

const emit = defineEmits<{
  'update:modelValue': [visible: boolean];
}>();

type Phase = 'confirm' | 'opening' | 'opened' | 'error';

const phase = ref<Phase>('confirm');
const flowError = ref<ApiError | null>(null);
const popupBlocked = ref(false);

watch(
  () => props.modelValue,
  (visible) => {
    if (visible) {
      reset();
    }
  },
);

function reset(): void {
  phase.value = 'confirm';
  flowError.value = null;
  popupBlocked.value = false;
}

function closeDialog(): void {
  emit('update:modelValue', false);
}

function errorHint(error: ApiError): string {
  switch (error.code) {
    case 'not_configured':
      return '设备当前未提供可用的 KVM 控制台（可能未配置或管理卡未启用图形控制台）。可重新执行连接测试刷新能力后再试。';
    case 'unsupported_operation':
      return '设备能力不支持或来源需求不匹配，无法创建远程控制台。可重新执行连接测试刷新能力。';
    case 'rate_limited':
      return '远程会话数量已达上限（每设备 1 个、每用户 3 个）或请求过于频繁，请稍后重试。';
    case 'validation_failed':
      return '设备当前状态不允许创建远程连接，请稍后重试。';
    default:
      return '';
  }
}

async function openConsole(): Promise<void> {
  if (phase.value === 'opening' || phase.value === 'opened') {
    return;
  }
  phase.value = 'opening';
  flowError.value = null;
  popupBlocked.value = false;
  // 同步打开占位标签页：await 之后再 window.open 会被浏览器弹窗拦截。
  const tab = window.open('', '_blank');
  try {
    const created = await request<LaunchCreateResponse>(
      `/devices/${props.deviceId}/launches`,
      { method: 'POST', body: { capability_key: props.capabilityKey } },
    );
    if (tab === null) {
      popupBlocked.value = true;
      phase.value = 'error';
      return;
    }
    tab.location.href = created.url;
    phase.value = 'opened';
  } catch (caught) {
    tab?.close();
    flowError.value = isApiError(caught) ? caught : null;
    phase.value = 'error';
  }
}

function retry(): void {
  reset();
  void openConsole();
}
</script>

<template>
  <el-dialog
    :model-value="modelValue"
    :title="`打开远程控制台：${capabilityKey}`"
    width="560px"
    :close-on-click-modal="false"
    @update:model-value="emit('update:modelValue', $event)"
  >
    <div class="launch-console" data-testid="launch-console-dialog">
      <p class="launch-console__requirement">需求编号：{{ requirementId }}</p>

      <template v-if="phase === 'confirm'">
        <p class="launch-console__hint">
          平台将签发 60 秒有效的一次性启动票据，并在新标签页打开设备管理卡的图形控制台入口
          （厂商页面可能要求再次认证；平台不代理、不注入凭据）。
        </p>
      </template>

      <template v-if="phase === 'opening'">
        <p class="launch-console__busy" data-testid="launch-busy">正在创建远程控制台票据…</p>
      </template>

      <template v-if="phase === 'opened'">
        <p class="launch-console__success" data-testid="launch-opened">
          已在新标签页打开设备控制台。若页面未跳转，请检查浏览器是否拦截了窗口。
        </p>
      </template>

      <template v-if="phase === 'error'">
        <p
          v-if="popupBlocked"
          class="launch-console__error"
          data-testid="launch-popup-blocked"
        >
          弹出窗口被浏览器拦截：控制台票据已创建，请允许本站弹出窗口后重新打开。
        </p>
        <p v-else-if="flowError !== null && errorHint(flowError)" class="launch-console__error">
          {{ errorHint(flowError) }}
        </p>
        <ErrorDetail v-if="flowError !== null" :error="flowError" data-testid="launch-error" />
      </template>
    </div>

    <template #footer>
      <el-button @click="closeDialog">关闭</el-button>
      <el-button
        v-if="phase === 'confirm'"
        type="primary"
        data-testid="launch-open"
        @click="openConsole"
      >
        打开控制台
      </el-button>
      <el-button
        v-if="phase === 'error' && !popupBlocked"
        type="primary"
        data-testid="launch-retry"
        @click="retry"
      >
        重试
      </el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.launch-console__requirement {
  margin: 0 0 10px;
  font-family: monospace;
  font-size: 12px;
  color: var(--warden-status-unknown);
}
.launch-console__hint {
  color: var(--warden-status-unknown);
  font-size: 13px;
  margin: 6px 0;
}
.launch-console__busy {
  color: var(--warden-status-unknown);
}
.launch-console__success {
  color: var(--warden-status-healthy);
}
.launch-console__error {
  color: var(--warden-status-critical);
  font-size: 13px;
  margin: 4px 0;
}
</style>
