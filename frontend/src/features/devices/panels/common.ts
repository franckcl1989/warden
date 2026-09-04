/**
 * 设备详情监控面板的公共数据访问（M2T7 / M5T5）。
 * 各面板独立获取自己页签的数据；列表类查询带服务端分页。
 */

import { request } from '@/api/client';
import type {
  DeviceMetricsLatestResponse,
  LatestComponentGroup,
} from '@/api/types';

export interface PageQuery {
  page: number;
  pageSize: number;
}

export function listQueryString(
  params: Record<string, string | number | null | undefined>,
): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === null || value === undefined || value === '') {
      continue;
    }
    query.set(key, String(value));
  }
  return query.toString();
}

/**
 * 一次取回设备全部“最新指标”分组（/metrics/latest 服务端按组件组
 * 分页，单页最多 100 组；端口/部件视图按组件行取每行最新指标，必须
 * 翻页取全——行数据缺失时如实显示“尚无观测”，绝不伪造值）。
 * 返回按组件 id 索引的分组 + 设备级（组件为 null）分组。
 */
export async function fetchAllLatestGroups(
  deviceId: string,
): Promise<{
  byComponent: Record<string, LatestComponentGroup>;
  device: LatestComponentGroup | null;
}> {
  const byComponent: Record<string, LatestComponentGroup> = {};
  let device: LatestComponentGroup | null = null;
  const pageSize = 100;
  for (let page = 1; ; page += 1) {
    const response = await request<DeviceMetricsLatestResponse>(
      `/devices/${deviceId}/metrics/latest?${listQueryString({ page, page_size: pageSize })}`,
    );
    for (const group of response.items) {
      const componentId = group.component?.id;
      if (componentId === undefined || componentId === null) {
        device = group;
      } else {
        byComponent[componentId] = group;
      }
    }
    if (page * pageSize >= response.total) {
      break;
    }
  }
  return { byComponent, device };
}
