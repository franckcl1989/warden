<script setup lang="ts">
import { computed } from 'vue';

import { apiBaseUrl } from '@/api/client';
import type { FileView } from '@/api/types';

// UI_SPEC §4 SensitiveFileLink：敏感文件授权下载链接。
// 观察员只能查看元数据不可下载（SECURITY/API_CONTRACT §8）；无权限时
// 显示明确原因而不是按钮。GET 下载携带同源会话 Cookie，不需要 CSRF。
const props = defineProps<{
  file: FileView;
  /** 当前用户对该文件是否有下载权限（调用方按角色/文件类型判断）。 */
  permitted: boolean;
}>();

const href = computed(() => `${apiBaseUrl()}/files/${props.file.id}/download`);
const linkText = computed(() => props.file.original_filename || props.file.id);
</script>

<template>
  <span class="sensitive-file-link">
    <a
      v-if="permitted && file.status === 'ready'"
      :href="href"
      :download="file.original_filename"
      class="sensitive-file-link__anchor"
    >
      {{ linkText }}
    </a>
    <span v-else-if="permitted && file.status !== 'ready'" class="sensitive-file-link__disabled">
      {{ file.status === 'uploading' ? '文件尚未就绪，不能下载' : '文件不可下载' }}
    </span>
    <span v-else class="sensitive-file-link__disabled">无下载权限</span>
  </span>
</template>

<style scoped>
.sensitive-file-link__anchor {
  color: var(--el-color-primary);
}
.sensitive-file-link__disabled {
  color: var(--warden-status-unknown);
}
</style>
