import {
  createRouter,
  createWebHistory,
  type NavigationGuard,
  type RouteRecordRaw,
  type Router,
  type RouterHistory,
} from 'vue-router';

import { setSessionExpiredHandler } from '@/api/client';
import { AlertsView } from '@/features/alerts';
import { AuditView } from '@/features/audit';
import { DevicesDetailView, DevicesListView, DevicesNewView } from '@/features/devices';
import { FilesView } from '@/features/files';
import { LoginView } from '@/features/login';
import { OperationsView } from '@/features/operations';
import { OverviewView } from '@/features/overview';
import { SystemView } from '@/features/system';
import { UsersView } from '@/features/users';
import { useAuthStore } from '@/stores/auth';

// 路由表对应 PRODUCT_DESIGN §2 信息架构的 11 个页面
export const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'login',
    component: LoginView,
    meta: { title: '登录', public: true },
  },
  { path: '/overview', name: 'overview', component: OverviewView, meta: { title: '总览' } },
  { path: '/devices', name: 'devices', component: DevicesListView, meta: { title: '设备' } },
  {
    path: '/devices/new',
    name: 'devices-new',
    component: DevicesNewView,
    meta: { title: '添加设备', adminOnly: true },
  },
  {
    path: '/devices/:id',
    name: 'device-detail',
    component: DevicesDetailView,
    meta: { title: '设备详情' },
  },
  { path: '/alerts', name: 'alerts', component: AlertsView, meta: { title: '当前问题' } },
  {
    path: '/operations',
    name: 'operations',
    component: OperationsView,
    meta: { title: '操作任务' },
  },
  { path: '/files', name: 'files', component: FilesView, meta: { title: '文件' } },
  {
    path: '/audit',
    name: 'audit',
    component: AuditView,
    meta: { title: '审计', adminOnly: true },
  },
  {
    path: '/users',
    name: 'users',
    component: UsersView,
    meta: { title: '用户与角色', adminOnly: true },
  },
  {
    path: '/system',
    name: 'system',
    component: SystemView,
    meta: { title: '系统状态', adminOnly: true },
  },
];

/**
 * 会话守卫（M1，PLT-01）：
 * - 未登录访问受保护页：尝试用会话 Cookie 恢复（GET /auth/me），仍失败则
 *   重定向 /login 并携带 ?next= 返回路径；
 * - 已登录访问 /login：回到总览；
 * - adminOnly 路由对非管理员硬拦截（UI_SPEC §2 管理员专属菜单）。
 */
export const authGuard: NavigationGuard = async (to) => {
  const auth = useAuthStore();
  if (to.meta.public) {
    if (to.name === 'login' && auth.isAuthenticated) {
      return { name: 'overview' };
    }
    return true;
  }
  if (!auth.isAuthenticated) {
    try {
      await auth.refreshMe();
    } catch {
      // 401 会话失效已由 client 处理器重定向；网络失败按未登录处理
    }
  }
  if (!auth.isAuthenticated) {
    return { name: 'login', query: { next: to.fullPath } };
  }
  if (to.meta.adminOnly && !auth.isAdmin) {
    return { name: 'overview' };
  }
  return true;
};

export function createAppRouter(history: RouterHistory = createWebHistory()): Router {
  const router = createRouter({ history, routes });
  router.beforeEach(authGuard);
  // 会话/CSRF 失效只能通过重新登录恢复：清理状态并回到登录页（带返回路径）
  setSessionExpiredHandler(() => {
    const auth = useAuthStore();
    auth.resetSession();
    void router.replace({
      name: 'login',
      query: { next: router.currentRoute.value.fullPath },
    });
  });
  return router;
}

export const router = createAppRouter();
