<script setup lang="ts">
import { ElButton, ElForm, ElFormItem, ElInput, ElMessage } from 'element-plus';
import { reactive, ref } from 'vue';

import ErrorDetail from '@/components/ErrorDetail.vue';
import type { ApiError } from '@/api/client';
import { useAuthStore } from '@/stores/auth';

// 强制改密视图：登录后 must_change_password 时先改密再进入应用（PLT-01）。
const auth = useAuthStore();

const emit = defineEmits<{ done: [] }>();

const props = defineProps<{ currentPassword?: string }>();

const MIN_PASSWORD_LENGTH = 12;

const form = reactive({
  currentPassword: props.currentPassword ?? '',
  newPassword: '',
  confirmPassword: '',
});
const submitting = ref(false);
const error = ref<ApiError | null>(null);

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
    emit('done');
  } catch (caught) {
    error.value = caught as ApiError;
  } finally {
    submitting.value = false;
  }
}
</script>

<template>
  <div class="change-password-panel">
    <h2 class="change-password-panel__title">首次登录需修改密码</h2>
    <p class="change-password-panel__hint">账号安全要求：设置新密码后才能进入系统</p>
    <ErrorDetail v-if="error" :error="error" class="change-password-panel__error" />
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
    </el-form>
    <el-button type="primary" :loading="submitting" @click="submit">确认修改</el-button>
  </div>
</template>

<style scoped>
.change-password-panel {
  max-width: 440px;
}
.change-password-panel__title {
  margin: 0 0 4px;
  font-size: 18px;
}
.change-password-panel__hint {
  margin: 0 0 16px;
  color: var(--warden-status-unknown);
  font-size: 13px;
}
.change-password-panel__error {
  margin-bottom: 12px;
}
</style>
