import { computed, ref } from 'vue';
import { defineStore } from 'pinia';

export type UserRole = 'admin' | 'operator' | 'viewer';

export interface CurrentUser {
  id: string;
  name: string;
  role: UserRole;
}

// 认证状态占位：M1（PLT-01）接入 /auth/* API 后替换
export const useAuthStore = defineStore('auth', () => {
  const user = ref<CurrentUser | null>(null);
  const sessionValid = ref(false);

  const isAuthenticated = computed(() => sessionValid.value && user.value !== null);

  async function login(): Promise<void> {
    // TODO M1（PLT-01）：调用 auth_login/auth_get_me 并刷新本地状态
  }

  async function logout(): Promise<void> {
    // TODO M1（PLT-01）：调用 auth_logout 并清空本地状态
  }

  return { user, sessionValid, isAuthenticated, login, logout };
});
