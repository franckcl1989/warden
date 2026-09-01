import { describe, expect, it } from 'vitest';
import { createMemoryHistory } from 'vue-router';

import { createAppRouter, routes } from '@/router';

// PRODUCT_DESIGN §2 信息架构的 11 个页面路由
const EXPECTED_PATHS = [
  '/login',
  '/overview',
  '/devices',
  '/devices/new',
  '/devices/:id',
  '/alerts',
  '/operations',
  '/files',
  '/audit',
  '/users',
  '/system',
];

describe('router 路由表', () => {
  it('包含 PRODUCT_DESIGN §2 的 11 个路由且路径精确匹配', () => {
    const paths = routes.map((route) => route.path).sort();
    expect(paths).toEqual([...EXPECTED_PATHS].sort());
    expect(routes).toHaveLength(11);
  });

  it('每个路由都有名称、中文标题和组件', () => {
    for (const route of routes) {
      expect(route.name).toBeTypeOf('string');
      expect(route.meta?.title).toBeTypeOf('string');
      expect(route.component).toBeDefined();
    }
  });

  it('认证守卫占位放行全部路由（M1 接入前未登录也可导航）', async () => {
    const router = createAppRouter(createMemoryHistory());
    await router.push('/overview');
    expect(router.currentRoute.value.path).toBe('/overview');
    await router.push('/devices/new');
    expect(router.currentRoute.value.path).toBe('/devices/new');
    await router.push('/devices/dev-1');
    expect(router.currentRoute.value.name).toBe('device-detail');
    await router.push('/users');
    expect(router.currentRoute.value.path).toBe('/users');
  });
});
