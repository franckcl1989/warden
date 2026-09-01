<script setup lang="ts">
import { ElEmpty } from 'element-plus';

// 页面加载状态壳；M2（PLT-03）接入实际加载/空/错误/无权限状态
const props = withDefaults(
  defineProps<{
    state?: 'idle' | 'loading' | 'empty' | 'error' | 'permission_denied';
  }>(),
  { state: 'idle' },
);
</script>

<template>
  <div class="async-state">
    <ElEmpty v-if="props.state === 'empty'" description="暂无数据" />
    <div v-else-if="props.state === 'loading'" class="async-state__hint">加载中</div>
    <div v-else-if="props.state === 'error'" class="async-state__hint">加载失败</div>
    <div v-else-if="props.state === 'permission_denied'" class="async-state__hint">无权限查看</div>
    <slot v-else />
  </div>
</template>

<style scoped>
.async-state__hint {
  color: var(--warden-status-unknown);
  padding: 48px 0;
  text-align: center;
}
</style>
