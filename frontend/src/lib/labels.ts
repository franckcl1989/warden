/**
 * 状态与枚举的中文展示文案（UI_SPEC：界面文案统一中文）。
 * 键全部来自 contracts/ 与 OpenAPI 生成的字符串值；未知值原样显示，
 * 不做业务猜测（能力状态只渲染 API 返回的内容）。
 */

export const DEVICE_TYPE_LABELS: Record<string, string> = {
  server: '服务器',
  synology_nas: '群晖 NAS',
  core_switch: '核心交换机',
  access_switch: '接入交换机',
};

export const ROLE_LABELS: Record<string, string> = {
  admin: '管理员',
  operator: '运维员',
  viewer: '观察员',
};

export const USER_STATUS_LABELS: Record<string, string> = {
  active: '启用',
  disabled: '停用',
  locked: '已锁定',
};

export const REACHABILITY_LABELS: Record<string, string> = {
  unknown: '未知',
  online: '在线',
  offline: '离线',
};

export const HEALTH_LABELS: Record<string, string> = {
  unknown: '未知',
  healthy: '健康',
  warning: '警告',
  critical: '严重',
};

export const READINESS_LABELS: Record<string, string> = {
  ready: '就绪',
  not_ready: '未就绪',
  misconfigured: '配置有误',
};

export const CAPABILITY_SUPPORT_LABELS: Record<string, string> = {
  supported: '支持',
  unsupported: '不支持',
  not_configured: '未配置',
};

/** 连接测试五阶段（PRODUCT_DESIGN §4.2 / UI_SPEC §10）。 */
export const PROBE_STAGE_LABELS: Record<string, string> = {
  network: '网络可达',
  tls: 'TLS/协议握手',
  auth: '认证',
  identity: '身份识别',
  capabilities: '能力发现',
};

/** 适配器展示名；fake.simple 明确标注开发用，绝不冒充真实硬件支持。 */
export const ADAPTER_LABELS: Record<string, string> = {
  'fake.simple': '测试适配器（开发用）',
};

export function label(map: Record<string, string>, value: string | null | undefined): string {
  if (value === null || value === undefined) {
    return '—';
  }
  return map[value] ?? value;
}
