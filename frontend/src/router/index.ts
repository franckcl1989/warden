import {
  createRouter,
  createWebHistory,
  type NavigationGuard,
  type RouteRecordRaw,
  type Router,
  type RouterHistory,
} from 'vue-router';

import { AlertsView } from '@/features/alerts';
import { AuditView } from '@/features/audit';
import { DevicesDetailView, DevicesListView, DevicesNewView } from '@/features/devices';
import { FilesView } from '@/features/files';
import { LoginView } from '@/features/login';
import { OperationsView } from '@/features/operations';
import { OverviewView } from '@/features/overview';
import { SystemView } from '@/features/system';
import { UsersView } from '@/features/users';

// 路由表对应 PRODUCT_DESIGN §2 信息架构的 11 个页面
export const routes: RouteRecordRaw[] = [
  { path: '/login', name: 'login', component: LoginView, meta: { title: '登录' } },
  { path: '/overview', name: 'overview', component: OverviewView, meta: { title: '总览' } },
  { path: '/devices', name: 'devices', component: DevicesListView, meta: { title: '设备' } },
  {
    path: '/devices/new',
    name: 'devices-new',
    component: DevicesNewView,
    meta: { title: '添加设备' },
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
  { path: '/audit', name: 'audit', component: AuditView, meta: { title: '审计' } },
  { path: '/users', name: 'users', component: UsersView, meta: { title: '用户与角色' } },
  { path: '/system', name: 'system', component: SystemView, meta: { title: '系统状态' } },
];

// 认证守卫占位：当前放行全部路由；M1（PLT-01）接入会话校验与角色权限
export const authGuard: NavigationGuard = () => {
  return true;
};

export function createAppRouter(history: RouterHistory = createWebHistory()): Router {
  const router = createRouter({ history, routes });
  router.beforeEach(authGuard);
  return router;
}

export const router = createAppRouter();
