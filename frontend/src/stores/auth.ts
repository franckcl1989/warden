import { computed, ref } from 'vue';
import { defineStore } from 'pinia';

import { request, setCsrfTokenProvider } from '@/api/client';
import type {
  ChangePasswordRequest,
  LoginResponse,
  MeResponse,
  ReauthResponse,
  UserView,
} from '@/api/types';

/**
 * 认证状态（M1，PLT-01）。
 * 会话只存放在 HttpOnly Cookie 中（浏览器管理）；CSRF 票据只存内存，
 * 页面刷新后由登录流程重新签发（SECURITY.md §2 禁止 localStorage 存 JWT）。
 */
export const useAuthStore = defineStore('auth', () => {
  const user = ref<UserView | null>(null);
  const permissions = ref<string[]>([]);
  const sessionExpiresAt = ref<string | null>(null);
  const reauthenticatedUntil = ref<string | null>(null);
  const mustChangePassword = ref(false);
  const csrfToken = ref<string | null>(null);

  const isAuthenticated = computed(() => user.value !== null && user.value !== undefined);
  const isAdmin = computed(() => user.value?.role === 'admin');

  // 变更请求自动携带内存中的 CSRF 票据（client.ts 只对变更方法注入）
  setCsrfTokenProvider(() => csrfToken.value);

  function applyLogin(payload: LoginResponse): void {
    user.value = payload.user;
    permissions.value = [];
    csrfToken.value = payload.csrf_token;
    sessionExpiresAt.value = payload.session_expires_at;
    mustChangePassword.value = payload.user.must_change_password;
    // 登录建立的新会话尚无复验记录，复验有效期为空
    reauthenticatedUntil.value = null;
  }

  /** 应用启动 / 路由守卫时恢复会话；me() 返回的会话不含新 CSRF 票据。 */
  async function refreshMe(): Promise<void> {
    const me = await request<MeResponse>('/auth/me');
    user.value = me.user;
    permissions.value = me.permissions;
    sessionExpiresAt.value = me.session_expires_at;
    mustChangePassword.value = me.user.must_change_password;
  }

  /** 认证状态整体失效（会话过期或 CSRF 丢失）；恢复只能重新登录。 */
  function resetSession(): void {
    user.value = null;
    permissions.value = [];
    csrfToken.value = null;
    sessionExpiresAt.value = null;
    reauthenticatedUntil.value = null;
    mustChangePassword.value = false;
  }

  /**
   * 服务端门禁确认强制改密（403 permission=password_change_required）。
   * 客户端本地状态与 /auth/me 不同步时以服务端为准（SECURITY §3）。
   */
  function markPasswordChangeRequired(): void {
    mustChangePassword.value = true;
  }

  async function login(username: string, password: string): Promise<void> {
    const payload = await request<LoginResponse>('/auth/login', {
      method: 'POST',
      body: { username, password },
    });
    applyLogin(payload);
  }

  async function logout(): Promise<void> {
    if (user.value === null) {
      resetSession();
      return;
    }
    try {
      await request('/auth/logout', { method: 'POST' });
    } finally {
      resetSession();
    }
  }

  async function changePassword(body: ChangePasswordRequest): Promise<void> {
    await request('/auth/password', { method: 'POST', body });
    mustChangePassword.value = false;
  }

  /** 高风险操作前 5 分钟内密码复验；返回服务端复验有效截止时间。 */
  async function reauthenticate(password: string): Promise<string> {
    const payload = await request<ReauthResponse>('/auth/reauth', {
      method: 'POST',
      body: { password },
    });
    reauthenticatedUntil.value = payload.reauthenticated_until;
    return payload.reauthenticated_until;
  }

  return {
    user,
    permissions,
    sessionExpiresAt,
    reauthenticatedUntil,
    mustChangePassword,
    csrfToken,
    isAuthenticated,
    isAdmin,
    login,
    logout,
    refreshMe,
    changePassword,
    reauthenticate,
    resetSession,
    markPasswordChangeRequired,
  };
});
