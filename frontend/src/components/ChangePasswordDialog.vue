<script setup lang="ts">
import { ElButton, ElDialog, ElForm, ElFormItem, ElInput, ElMessage } from 'element-plus';
import { reactive, ref } from 'vue';

import ErrorDetail from '@/components/ErrorDetail.vue';
import type { ApiError } from '@/api/client';
import { useAuthStore } from '@/stores/auth';

// 修改当前用户密码（PLT-01 /auth/password）。密码 ≥12 位（SECURITY.md §2）。
const auth = useAuthStore();

const visible = defineModel<boolean>({ default: false });

const form = reactive({ currentPassword: '', newPassword: '', confirmPassword: '' });
const submitting = ref(false);
const error = ref<ApiError | null>(null);

const MIN_PASSWORD_LENGTH = 12;

function validate(): string | null {
  if (!form.currentPassword) return '请输入当前密码';
  if (form.newPassword.length < MIN_PASSWORD_LENGTH)
    return `新密码长度至少 ${MIN_PASSWORD_LENGTH} 位`;
  if (
    auth.user &&
    auth.user.username &&
    form.newPassword.toLowerCase().includes(auth.user.username.toLowerCase())
  ) {
    return '新密码不能包含用户名';
  }
  if (form.newPassword !== form.confirmPassword) return '两次输入的新密码不一致';
  return null;
}

async function submit(): Promise<void> {
  const message = validate();
  if (message) {
    error.value = null;
    ElMessage.warning(message);
    return;
  }
  submitting.value = true;
  error.value = null;
  try {
    await auth.changePassword({
      current_password: form.currentPassword,
      new_password: form.newPassword,
    });
    ElMessage.success('密码已修改');
    form.currentPassword = '';
    form.newPassword = '';
    form.confirmPassword = '';
    visible.value = false;
  } catch (caught) {
    error.value = caught as ApiError;
  } finally {
    submitting.value = false;
  }
}
</script>

<template>
  <el-dialog v-model="visible" title="修改密码" width="440px" :close-on-click-modal="false">
    <ErrorDetail v-if="error" :error="error" class="change-password-dialog__error" />
    <el-form label-width="96px" @submit.prevent="submit">
      <el-form-item label="当前密码">
        <el-input
          v-model="form.currentPassword"
          type="password"
          show-password
          autocomplete="current-password"
        />
      </el-form-item>
      <el-form-item label="新密码">
        <el-input
          v-model="form.newPassword"
          type="password"
          show-password
          autocomplete="new-password"
        />
      </el-form-item>
      <el-form-item label="确认新密码">
        <el-input
          v-model="form.confirmPassword"
          type="password"
          show-password
          autocomplete="new-password"
        />
      </el-form-item>
      <p class="change-password-dialog__hint">
        密码长度至少 12 位，不能包含用户名，不能是常见弱密码
      </p>
    </el-form>
    <template #footer>
      <el-button @click="visible = false">取消</el-button>
      <el-button type="primary" :loading="submitting" @click="submit">确认修改</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.change-password-dialog__error {
  margin-bottom: 12px;
}
.change-password-dialog__hint {
  margin: 0 0 0 96px;
  color: var(--warden-status-unknown);
  font-size: 12px;
}
</style>
