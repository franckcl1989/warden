<script setup lang="ts">
import { ElButton, ElDialog } from 'element-plus';
import { computed, ref, watch } from 'vue';
import { useRouter } from 'vue-router';

import ErrorDetail from '@/components/ErrorDetail.vue';
import { isApiError, request, type ApiError } from '@/api/client';
import type { LaunchCreateResponse } from '@/api/types';

// 远程连接启动流程（M3T4/M4T4/M5T4 / PLT-09，API_CONTRACT.md §7）：
// console.kvm.open（KVM 控制台）与 console.dsm.open（DSM 管理界面）共用同一
// 一次性票据流程：点击"打开"→ 同步占位新标签页（避免弹窗拦截）→ POST
// /devices/{id}/launches → 成功后把新标签页导航到返回的一次性消费 URL
// （GET /launches/{id} 返回 HTML 自动跳转页，厂商 URL 不进入 SPA 状态，且
// 每次只可读取一次）。console.ssh.open / console.telnet.open（M5T4）签发
// 浏览器终端票据：SPA 内跳转终端页 /terminal/sessions/{ticket} 并建立
// WebSocket（服务端校验 Origin + 会话 Cookie + 一次性票据）。Telnet 为弱
// 协议：开启前持续提示明文风险（SECURITY.md §6 / ADR-007）。错误按稳定
// 错误码渲染中文提示；其他错误走 ErrorDetail。
const props = defineProps<{
  modelValue: boolean;
  deviceId: string;
  capabilityKey: string;
  requirementId: string;
}>();

const emit = defineEmits<{
  'update:modelValue': [visible: boolean];
}>();

const router = useRouter();

type Phase = 'confirm' | 'opening' | 'opened' | 'error';

const phase = ref<Phase>('confirm');
const flowError = ref<ApiError | null>(null);
const popupBlocked = ref(false);

/** 目标类型（能力键派生）：DSM 管理界面 / KVM 图形控制台 / SSH / Telnet 终端。 */
const isDsmConsole = computed(() => props.capabilityKey === 'console.dsm.open');
const isSshTerminal = computed(() => props.capabilityKey === 'console.ssh.open');
const isTelnetTerminal = computed(() => props.capabilityKey === 'console.telnet.open');
const isTerminal = computed(() => isSshTerminal.value || isTelnetTerminal.value);

function confirmHint(): string {
  if (isTerminal.value) {
    const weak = isTelnetTerminal.value
      ? 'Telnet 为明文弱协议：凭据与命令不经加密传输，仅应在受控管理网内使用。'
      : '';
    return `平台将签发 60 秒有效的一次性终端票据并在浏览器中打开 SSH 终端。${weak}`;
  }
  if (isDsmConsole.value) {
    return '平台将签发 60 秒有效的一次性启动票据，并在新标签页打开设备的 DSM 管理界面'
      + '（平台不注入密码，DSM 可能要求再次登录）。';
  }
  return '平台将签发 60 秒有效的一次性启动票据，并在新标签页打开设备管理卡的图形控制台入口'
    + '（厂商页面可能要求再次认证；平台不代理、不注入凭据）。';
}

function notConfiguredHint(): string {
  if (isTerminal.value) {
    return '设备当前未配置可用的 SSH/Telnet 终端通道（如端口、凭据、主机指纹或 Telnet 设备开关），'
      + '或 Telnet 未在该部署启用。可重新执行连接测试刷新能力后再试。';
  }
  if (isDsmConsole.value) {
    return '设备当前未提供可用的 DSM 管理界面（可能未配置或管理地址不可达）。可重新执行连接测试刷新能力后再试。';
  }
  return '设备当前未提供可用的 KVM 控制台（可能未配置或管理卡未启用图形控制台）。可重新执行连接测试刷新能力后再试。';
}

function openButtonLabel(): string {
  if (isDsmConsole.value) {
    return '打开管理界面';
  }
  return isTerminal.value ? '打开终端' : '打开控制台';
}

function dialogTitle(): string {
  if (isTerminal.value) {
    return isTelnetTerminal.value ? '打开 Telnet 终端（弱协议）' : '打开 SSH 终端';
  }
  return isDsmConsole.value ? `打开 DSM 管理界面：${props.capabilityKey}` : `打开远程控制台：${props.capabilityKey}`;
}

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
      return notConfiguredHint();
    case 'unsupported_operation':
      return '设备能力不支持或来源需求不匹配，无法创建远程连接。可重新执行连接测试刷新能力。';
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
  // 终端票据无需新标签页；URL 类启动同步打开占位标签页（避免弹窗拦截）。
  const tab = isTerminal.value ? null : window.open('', '_blank');
  try {
    const created = await request<LaunchCreateResponse>(
      `/devices/${props.deviceId}/launches`,
      { method: 'POST', body: { capability_key: props.capabilityKey } },
    );
    if (isTerminal.value) {
      // 同一 SPA 内进入终端页：WS 由页面按 ticket 建立（同源 Cookie）。
      emit('update:modelValue', false);
      await router.push({ name: 'terminal-sessions', params: { ticket: created.launch_id } });
      return;
    }
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
    :title="dialogTitle()"
    width="560px"
    :close-on-click-modal="false"
    @update:model-value="emit('update:modelValue', $event)"
  >
    <div class="launch-console" data-testid="launch-console-dialog">
      <p class="launch-console__requirement">需求编号：{{ requirementId }}</p>

      <template v-if="phase === 'confirm'">
        <p class="launch-console__hint">
          {{ confirmHint() }}
        </p>
      </template>

      <template v-if="phase === 'opening'">
        <p class="launch-console__busy" data-testid="launch-busy">正在创建远程连接票据…</p>
      </template>

      <template v-if="phase === 'opened'">
        <p class="launch-console__success" data-testid="launch-opened">
          {{ isDsmConsole ? '已在新标签页打开 DSM 管理界面。' : '已在新标签页打开设备控制台。' }}
          若页面未跳转，请检查浏览器是否拦截了窗口。
        </p>
      </template>

      <template v-if="phase === 'error'">
        <p
          v-if="popupBlocked"
          class="launch-console__error"
          data-testid="launch-popup-blocked"
        >
          弹出窗口被浏览器拦截：启动票据已创建，请允许本站弹出窗口后重新打开。
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
        {{ openButtonLabel() }}
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
