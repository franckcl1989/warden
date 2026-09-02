/**
 * 设备详情监控面板的公共数据访问（M2T7）。
 * 各面板独立获取自己页签的数据；列表类查询带服务端分页。
 */

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
