<script setup lang="ts">
import { ElButton, ElCard, ElMessage } from 'element-plus';
import { useRoute, useRouter } from 'vue-router';

import { useAuthStore } from '@/stores/auth';
import ChangePasswordPanel from '@/features/login/ChangePasswordPanel.vue';

// 强制改密页（SECURITY §2）：会话恢复（页面刷新）后发现 must_change_password
// 时的引导入口。面板复用登录页的改密流程；恢复的会话没有内存中的登录密码，
// 当前密码由用户重新输入。
const auth = useAuthStore();
const route = useRoute();
const router = useRouter();

function nextPath(): string {
  const next = route.query.next;
  return typeof next === 'string' && next.startsWith('/') && next !== '/change-password'
    ? next
    : '/overview';
}

async function onPasswordChanged(): Promise<void> {
  await router.replace(nextPath());
}

async function onLogout(): Promise<void> {
  await auth.logout();
  ElMessage.success('已退出登录');
  await router.replace({ name: 'login' });
}
</script>

<template>
  <div class="change-password-page">
    <el-card class="change-password-page__card">
      <ChangePasswordPanel @done="onPasswordChanged" />
      <p class="change-password-page__hint">
        会话恢复后请重新输入当前密码；如提交被拒绝，重新登录后再修改
      </p>
      <el-button link type="primary" data-testid="change-password-logout" @click="onLogout">
        退出登录
      </el-button>
    </el-card>
  </div>
</template>

<style scoped>
.change-password-page {
  padding: 48px 16px;
  display: flex;
  justify-content: center;
}
.change-password-page__card {
  width: 440px;
}
.change-password-page__hint {
  margin: 12px 0 4px;
  color: var(--warden-status-unknown);
  font-size: 12px;
}
</style>
