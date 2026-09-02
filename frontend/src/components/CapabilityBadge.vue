<script setup lang="ts">
import { ElTag, ElTooltip } from 'element-plus';

import { CAPABILITY_SUPPORT_LABELS, label } from '@/lib/labels';

// 能力支持状态徽标（PRODUCT_DESIGN §5.1）。
// support_state 只渲染 API 返回的值；原因（reason_code/detail）悬停展示。
const props = defineProps<{
  supportState: string | null | undefined;
  reasonCode?: string | null;
  detail?: string | null;
}>();

const tagType = (): 'success' | 'warning' | 'info' => {
  if (props.supportState === 'supported') return 'success';
  if (props.supportState === 'not_configured') return 'warning';
  return 'info';
};

const reasonText = (): string | null => {
  const parts: string[] = [];
  if (props.reasonCode) parts.push(`原因码：${props.reasonCode}`);
  if (props.detail) parts.push(props.detail);
  return parts.length > 0 ? parts.join('；') : null;
};
</script>

<template>
  <el-tooltip :content="reasonText() ?? '无附加原因'" placement="top">
    <el-tag :type="tagType()" size="small">
      {{ label(CAPABILITY_SUPPORT_LABELS, supportState) }}
    </el-tag>
  </el-tooltip>
</template>
