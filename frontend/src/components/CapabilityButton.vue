<script setup lang="ts">
import { ElButton, ElTooltip } from 'element-plus';
import { computed } from 'vue';

import { CAPABILITY_SUPPORT_LABELS, label } from '@/lib/labels';

// UI_SPEC §4/§8 CapabilityButton：能力状态、权限、禁用原因和需求编号。
// 只渲染 API 返回的 support_state；被禁用的原因（reason_code/detail 或调用方
// 给出的里程碑原因）悬停展示；点击后由父级打开真实预览流程。
const props = withDefaults(
  defineProps<{
    capabilityKey: string;
    requirementId: string;
    requirementTitle?: string | null;
    supportState: string | null | undefined;
    reasonCode?: string | null;
    detail?: string | null;
    disabledReason?: string;
  }>(),
  {
    requirementTitle: undefined,
    reasonCode: undefined,
    detail: undefined,
    disabledReason: undefined,
  },
);

const emit = defineEmits<{ click: [key: string] }>();

const disabled = computed(
  () => props.supportState !== 'supported' || props.disabledReason !== undefined,
);

const tooltipParts = computed(() => {
  const parts: string[] = [];
  if (props.disabledReason) {
    parts.push(props.disabledReason);
  }
  if (props.reasonCode) {
    parts.push(`原因码：${props.reasonCode}`);
  }
  if (props.detail) {
    parts.push(props.detail);
  }
  return parts;
});
</script>

<template>
  <div class="capability-button">
    <el-tooltip
      :content="tooltipParts.join('；') || '该能力支持，可发起操作'"
      placement="top"
      :disabled="tooltipParts.length === 0"
    >
      <div class="capability-button__control">
        <el-button
          :disabled="disabled"
          :data-testid="`capability-${capabilityKey}`"
          @click="emit('click', capabilityKey)"
        >
          {{ capabilityKey }}
        </el-button>
      </div>
    </el-tooltip>
    <div class="capability-button__meta">
      <span class="capability-button__requirement">{{ requirementId }}</span>
      <span
        class="capability-button__support"
        :class="`capability-button__support--${supportState}`"
      >
        {{ label(CAPABILITY_SUPPORT_LABELS, supportState) }}
      </span>
    </div>
  </div>
</template>

<style scoped>
.capability-button__control {
  display: inline-flex;
}
.capability-button__meta {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-top: 2px;
  font-size: 12px;
}
.capability-button__requirement {
  font-family: monospace;
  color: var(--warden-status-unknown);
}
.capability-button__support {
  font-size: 12px;
}
.capability-button__support--supported {
  color: var(--warden-status-healthy);
}
.capability-button__support--unsupported,
.capability-button__support--not_configured {
  color: var(--warden-status-warning);
}
</style>
