<script setup lang="ts">
import { ElTag } from 'element-plus';

import { REACHABILITY_LABELS, label } from '@/lib/labels';

// 可达性徽标（GLOSSARY：reachability）。与健康徽标分离，未知 ≠ 健康。
const props = defineProps<{ reachability: string | null | undefined }>();

const tagType = (): 'success' | 'danger' | 'info' => {
  if (props.reachability === 'online') return 'success';
  if (props.reachability === 'offline') return 'danger';
  return 'info';
};
</script>

<template>
  <el-tag :type="tagType()" size="small">{{ label(REACHABILITY_LABELS, reachability) }}</el-tag>
</template>
