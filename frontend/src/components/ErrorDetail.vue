<script setup lang="ts">
import { ElAlert } from 'element-plus';

import type { ApiError } from '@/api/client';

// UI_SPEC §10：错误信息包含稳定错误码、用户说明、请求 ID 和用户能做的下一步。
// 下一步提示是固定界面文案，客户端逻辑仍只依赖 code（contracts/error-codes.json）。

const NEXT_STEP: Record<string, string> = {
  session_expired: '会话已过期，请重新登录后重试',
  unauthenticated: '未登录或会话不存在，请重新登录',
  csrf_failed: '安全校验失败，请重新登录后重试',
  permission_denied: '当前账号无此权限，如需操作请联系管理员',
  rate_limited: '请求过于频繁，请稍后重试',
  version_conflict: '数据已被其他用户修改，请刷新后重新操作',
  network_unreachable: '设备网络不可达，请检查管理地址与网络后重试',
  tls_validation_failed: 'TLS 校验失败，请核对证书指纹或连接配置',
  authentication_failed: '设备认证失败，请核对凭据后重试',
  permission_denied_by_device: '设备拒绝了当前账号权限，请核对设备侧授权',
  protocol_error: '协议交互失败，请核对协议配置后重试',
  unsupported_capability: '设备或固件不支持该能力',
  not_configured: '缺少必要配置，请补齐后重试',
  device_busy: '设备正在执行其他操作，请稍后重试',
  validation_failed: '参数校验失败，请按提示修正后重试',
  maintenance_mode: '系统维护中，请稍后重试',
  dependency_unavailable: '服务依赖暂不可用，请稍后重试',
  storage_unavailable: '存储暂不可用，请稍后重试',
  internal_error: '服务内部错误，请稍后重试',
  resource_not_found: '资源不存在或已被删除',
  idempotency_conflict: '该操作已提交，请勿重复提交',
  preview_stale: '操作预览已失效，请重新预览',
  operation_failed: '设备操作失败，请查看任务详情',
  ambiguous_result: '操作结果待核验，请查看任务详情',
  reauthentication_required: '高风险操作需要重新验证密码',
};

defineProps<{ error: ApiError }>();
</script>

<template>
  <el-alert class="error-detail" type="error" :closable="false" show-icon>
    <template #title>
      <span class="error-detail__message">{{ error.message }}</span>
    </template>
    <div class="error-detail__body">
      <p class="error-detail__next">
        {{ NEXT_STEP[error.code] ?? '请稍后重试或联系管理员' }}
      </p>
      <p class="error-detail__meta">错误码：{{ error.code }} · 请求 ID：{{ error.request_id }}</p>
    </div>
  </el-alert>
</template>

<style scoped>
.error-detail__body {
  margin-top: 4px;
}
.error-detail__next {
  margin: 0 0 4px;
}
.error-detail__meta {
  margin: 0;
  color: var(--warden-status-unknown);
  font-size: 12px;
}
</style>
