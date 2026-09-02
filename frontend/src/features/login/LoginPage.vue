<script setup lang="ts">
import { ElButton, ElCard, ElForm, ElFormItem, ElInput } from 'element-plus';
import { reactive, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import ErrorDetail from '@/components/ErrorDetail.vue';
import type { ApiError } from '@/api/client';
import { useAuthStore } from '@/stores/auth';
import ChangePasswordPanel from '@/features/login/ChangePasswordPanel.vue';

// 登录页（PLT-01，PRODUCT_DESIGN §2 /login）。
const auth = useAuthStore();
const route = useRoute();
const router = useRouter();

const form = reactive({ username: '', password: '' });
const submitting = ref(false);
const error = ref<ApiError | null>(null);
const forcedChange = ref(false);

function nextPath(): string {
  const next = route.query.next;
  return typeof next === 'string' && next.startsWith('/') ? next : '/overview';
}

async function submit(): Promise<void> {
  if (!form.username || !form.password) {
    return;
  }
  submitting.value = true;
  error.value = null;
  try {
    await auth.login(form.username, form.password);
    if (auth.mustChangePassword) {
      forcedChange.value = true;
    } else {
      await router.replace(nextPath());
    }
  } catch (caught) {
    error.value = caught as ApiError;
  } finally {
    submitting.value = false;
  }
}

async function onPasswordChanged(): Promise<void> {
  await router.replace(nextPath());
}
</script>

<template>
  <div class="login-page">
    <el-card class="login-page__card">
      <h1 class="login-page__title">Warden</h1>
      <p class="login-page__subtitle">边端硬件监控与管理平台</p>
      <ChangePasswordPanel
        v-if="forcedChange"
        :current-password="form.password"
        @done="onPasswordChanged"
      />
      <template v-else>
        <ErrorDetail v-if="error" :error="error" class="login-page__error" />
        <el-form label-position="top" @submit.prevent="submit">
          <el-form-item label="用户名">
            <el-input v-model="form.username" autocomplete="username" data-testid="username" />
          </el-form-item>
          <el-form-item label="密码">
            <el-input
              v-model="form.password"
              type="password"
              show-password
              autocomplete="current-password"
              data-testid="password"
            />
          </el-form-item>
        </el-form>
        <el-button
          type="primary"
          class="login-page__submit"
          :loading="submitting"
          data-testid="login-submit"
          @click="submit"
        >
          登 录
        </el-button>
      </template>
    </el-card>
  </div>
</template>

<style scoped>
.login-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--el-bg-color-page);
}
.login-page__card {
  width: 380px;
}
.login-page__title {
  margin: 0;
  text-align: center;
  font-size: 24px;
}
.login-page__subtitle {
  margin: 4px 0 24px;
  text-align: center;
  color: var(--warden-status-unknown);
  font-size: 13px;
}
.login-page__error {
  margin-bottom: 12px;
}
.login-page__submit {
  width: 100%;
}
</style>
