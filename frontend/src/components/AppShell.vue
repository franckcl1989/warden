<script setup lang="ts">
import { ElDropdown, ElDropdownItem, ElDropdownMenu, ElMenu, ElMenuItem } from 'element-plus';
import { computed, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import ChangePasswordDialog from '@/components/ChangePasswordDialog.vue';
import { ROLE_LABELS, label } from '@/lib/labels';
import { useAuthStore } from '@/stores/auth';

// UI_SPEC §2 全局框架：左侧 224px 可收起导航 + 顶栏用户菜单。
const auth = useAuthStore();
const route = useRoute();
const router = useRouter();

const collapsed = ref(false);
const changePasswordVisible = ref(false);

interface NavItem {
  path: string;
  title: string;
  adminOnly: boolean;
}

const NAV_ITEMS: NavItem[] = [
  { path: '/overview', title: '总览', adminOnly: false },
  { path: '/devices', title: '设备', adminOnly: false },
  { path: '/alerts', title: '当前问题', adminOnly: false },
  { path: '/operations', title: '操作任务', adminOnly: false },
  { path: '/files', title: '文件', adminOnly: false },
  { path: '/audit', title: '审计', adminOnly: true },
  { path: '/users', title: '用户与角色', adminOnly: true },
  { path: '/system', title: '系统状态', adminOnly: true },
];

const visibleNav = computed(() => NAV_ITEMS.filter((item) => !item.adminOnly || auth.isAdmin));

const activePath = computed(() => {
  if (route.path.startsWith('/devices')) return '/devices';
  return route.path;
});

async function onLogout(): Promise<void> {
  await auth.logout();
  await router.replace({ name: 'login' });
}
</script>

<template>
  <el-container class="app-shell">
    <el-aside :width="collapsed ? '64px' : '224px'" class="app-shell__aside">
      <div class="app-shell__brand">Warden</div>
      <el-menu class="app-shell__menu" :collapse="collapsed" :default-active="activePath" router>
        <el-menu-item v-for="item in visibleNav" :key="item.path" :index="item.path">
          <template #title>{{ item.title }}</template>
        </el-menu-item>
      </el-menu>
      <button
        class="app-shell__collapse"
        type="button"
        :aria-label="collapsed ? '展开侧栏' : '收起侧栏'"
        @click="collapsed = !collapsed"
      >
        {{ collapsed ? '»' : '«' }}
      </button>
    </el-aside>
    <el-container>
      <el-header class="app-shell__header">
        <h1 class="app-shell__title">{{ route.meta.title ?? '' }}</h1>
        <el-dropdown v-if="auth.user" trigger="click">
          <span class="app-shell__user">
            {{ auth.user.display_name }}（{{ label(ROLE_LABELS, auth.user.role) }}） ▾
          </span>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item @click="changePasswordVisible = true">修改密码</el-dropdown-item>
              <el-dropdown-item divided @click="onLogout">退出登录</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </el-header>
      <el-main class="app-shell__main">
        <slot />
      </el-main>
    </el-container>
    <ChangePasswordDialog v-model="changePasswordVisible" />
  </el-container>
</template>

<style scoped>
.app-shell {
  height: 100vh;
}
.app-shell__aside {
  display: flex;
  flex-direction: column;
  border-right: 1px solid var(--el-border-color-light);
  transition: width 0.2s;
  overflow: hidden;
}
.app-shell__brand {
  height: 48px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
  font-size: 16px;
  flex-shrink: 0;
}
.app-shell__menu {
  flex: 1;
  border-right: none;
}
.app-shell__collapse {
  border: none;
  background: transparent;
  cursor: pointer;
  height: 40px;
  color: var(--warden-status-unknown);
}
.app-shell__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  border-bottom: 1px solid var(--el-border-color-light);
}
.app-shell__title {
  margin: 0;
  font-size: 16px;
  font-weight: 600;
}
.app-shell__user {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  cursor: pointer;
  outline: none;
}
.app-shell__main {
  background: var(--el-bg-color-page);
}
</style>
