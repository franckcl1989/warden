<script setup lang="ts">
import { ElButton, ElEmpty, ElSkeleton } from 'element-plus';
import { computed } from 'vue';

import ErrorDetail from '@/components/ErrorDetail.vue';
import { isApiError, type ApiError } from '@/api/client';

// UI_SPEC §4 AsyncState：loading/empty/error/permission_denied 状态壳；
// ready/idle 时渲染默认插槽。
const props = withDefaults(
  defineProps<{
    state?: 'idle' | 'loading' | 'empty' | 'ready' | 'error' | 'permission_denied' | 'not_found';
    error?: ApiError | null;
    emptyText?: string;
    emptyAction?: string;
  }>(),
  {
    state: undefined,
    error: null,
    emptyText: '暂无数据',
    emptyAction: undefined,
  },
);

const emit = defineEmits<{ retry: [] }>();

/** 服务端信封错误；网络失败等非 ApiError 一律走通用提示 */
const serverError = computed<ApiError | null>(() => (isApiError(props.error) ? props.error : null));
</script>

<template>
  <div class="async-state">
    <ElSkeleton v-if="props.state === 'loading'" :rows="5" animated />
    <ElEmpty v-else-if="props.state === 'empty'" :description="props.emptyText">
      <ElButton v-if="props.emptyAction" type="primary" plain @click="emit('retry')">
        {{ props.emptyAction }}
      </ElButton>
    </ElEmpty>
    <div v-else-if="props.state === 'error'" class="async-state__error">
      <ErrorDetail v-if="serverError" :error="serverError" />
      <p v-else class="async-state__hint">网络连接失败或服务不可达，请稍后重试</p>
      <ElButton type="primary" plain @click="emit('retry')">重试</ElButton>
    </div>
    <div v-else-if="props.state === 'permission_denied'" class="async-state__hint">
      无权限查看该页面
    </div>
    <div v-else-if="props.state === 'not_found'" class="async-state__hint">资源不存在</div>
    <slot v-else />
  </div>
</template>

<style scoped>
.async-state {
  min-height: 120px;
}
.async-state__error {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 12px;
}
.async-state__hint {
  color: var(--warden-status-unknown);
  padding: 32px 0;
  text-align: center;
}
</style>
