/**
 * 设备详情页签配置（PRODUCT_DESIGN §5.2-5.5）。
 *
 * 页签结构按四类设备固定：通用页签（概览/指标/组件/事件/采集/操作）+ 类型专属
 * 页签。类型专属页签把该类型的监控需求（capabilities.json 的 *-MON-* 需求）和
 * 组件种类分组成 PRODUCT_DESIGN 定义的视图。MON 需求 ID 列表由生成的
 * contracts.ts（REQUIREMENTS）按 device_type + kind=monitoring 推导，不手写
 * 第二份 DTO；本文件只表达"需求 → 页签"的界面信息架构归属。
 */
import { REQUIREMENTS } from '@/api/generated/contracts';

export type TabSectionKind =
  | 'overview'
  | 'metric-groups'
  | 'components'
  | 'ports'
  | 'poe'
  | 'events'
  | 'backup-status'
  | 'collection-runs'
  | 'operations';

export interface TabSection {
  kind: TabSectionKind;
  /** metric-groups：该分区渲染的 MON 需求 ID 列表。 */
  requirementIds?: string[];
  /** components / ports / poe：按 kind 过滤的组件行（端口表视图）。 */
  kinds?: string[];
  /** events：可选事件类型过滤（如交换机关键日志）。 */
  eventTypes?: string[];
}

export interface DeviceTabDef {
  id: string;
  title: string;
  sections: TabSection[];
}

/** 概览页签承载的"状态摘要"MON 需求（PRODUCT_DESIGN 各类概览内容）。 */
export const OVERVIEW_MON_REQUIREMENTS: Record<string, string[]> = {
  // §5.2 服务器概览：综合健康(SRV-MON-01) + 温度摘要(SRV-MON-02) + 资产/入侵与告警灯(SRV-MON-07)
  server: ['SRV-MON-01', 'SRV-MON-02', 'SRV-MON-07'],
  synology_nas: ['NAS-MON-03', 'NAS-MON-05', 'NAS-MON-06'],
  core_switch: ['CORE-MON-01', 'CORE-MON-04'],
  access_switch: ['ACCESS-MON-01', 'ACCESS-MON-04'],
};

/** 核心/接入交换机、NAS 的"日志与事件"归属（PRODUCT_DESIGN §5.3-5.5）。 */
const SWITCH_EVENT_TYPES = ['event.port_flap', 'event.device_restart', 'event.auth_failure'];
const NAS_LOG_EVENT_TYPES = ['event.system_log'];

/** 该类型全部监控需求 ID（按生成注册表推导，保序）。 */
export function monitoringRequirementIds(deviceType: string): string[] {
  return Object.entries(REQUIREMENTS)
    .filter(
      ([, requirement]) =>
        requirement.kind === 'monitoring' && requirement.deviceType === deviceType,
    )
    .map(([id]) => id);
}

const SERVER_EXTRA: DeviceTabDef[] = [
  {
    id: 'temp-memory',
    title: '温度与内存',
    sections: [{ kind: 'metric-groups', requirementIds: ['SRV-MON-02', 'SRV-MON-03'] }],
  },
  {
    id: 'storage',
    title: '存储',
    sections: [
      { kind: 'components', kinds: ['drive'] },
      { kind: 'metric-groups', requirementIds: ['SRV-MON-04'] },
    ],
  },
  {
    id: 'power-fan',
    title: '电源与风扇',
    sections: [
      { kind: 'metric-groups', requirementIds: ['SRV-MON-05', 'SRV-MON-06'] },
      { kind: 'components', kinds: ['psu', 'fan'] },
    ],
  },
];

const NAS_EXTRA: DeviceTabDef[] = [
  {
    id: 'disks',
    title: '磁盘',
    sections: [
      { kind: 'components', kinds: ['disk'] },
      { kind: 'metric-groups', requirementIds: ['NAS-MON-01'] },
    ],
  },
  {
    id: 'storage',
    title: '存储',
    sections: [{ kind: 'metric-groups', requirementIds: ['NAS-MON-02', 'NAS-MON-04'] }],
  },
  {
    id: 'tasks-logs',
    title: '任务与日志',
    sections: [
      // 备份/快照任务状态视图（NAS-ACT-05）：渲染最近一次 backup.status.refresh
      // 成功任务持久化的清单证据（M4T3 决策：任务 evidence 即结果存储，无独立表）。
      { kind: 'backup-status' },
      { kind: 'events', eventTypes: NAS_LOG_EVENT_TYPES },
    ],
  },
];

const CORE_EXTRA: DeviceTabDef[] = [
  {
    id: 'ports',
    title: '端口',
    sections: [
      // 端口表视图（M5T5）：按行展示端口组件 + 每行最新指标 chips
      // （管理/运行状态、流量、CRC、错误、丢包 — CORE-MON-02）。
      { kind: 'ports', requirementIds: ['CORE-MON-02'], kinds: ['interface'] },
    ],
  },
  {
    id: 'transceivers',
    title: '光模块',
    sections: [
      // 光模块表视图（M5T5）：CORE-MON-03（收发功率/温度/电压/电流）。
      { kind: 'ports', requirementIds: ['CORE-MON-03'], kinds: ['transceiver'] },
    ],
  },
  {
    id: 'layer2-logs',
    title: '二层与日志',
    sections: [
      { kind: 'metric-groups', requirementIds: ['CORE-MON-05'] },
      { kind: 'events', eventTypes: SWITCH_EVENT_TYPES },
    ],
  },
];

const ACCESS_EXTRA: DeviceTabDef[] = [
  {
    id: 'ports',
    title: '端口',
    sections: [
      // 端口表视图（M5T5）：ACCESS-MON-02（状态/流量/错误）。
      { kind: 'ports', requirementIds: ['ACCESS-MON-02'], kinds: ['interface'] },
    ],
  },
  {
    id: 'poe',
    title: 'PoE',
    sections: [
      // PoE 视图（M5T5）：设备级总功耗/预算/占比/告警摘要 +
      // 逐端口供电与单端口功耗行（ACCESS-MON-03）。
      { kind: 'poe', requirementIds: ['ACCESS-MON-03'], kinds: ['poe_port'] },
    ],
  },
  {
    id: 'transceivers',
    title: '光模块',
    sections: [
      // 光模块表视图（M5T5）：ACCESS-MON-05（上联口收发功率）。
      { kind: 'ports', requirementIds: ['ACCESS-MON-05'], kinds: ['transceiver'] },
    ],
  },
];

const EXTRA_BY_TYPE: Record<string, DeviceTabDef[]> = {
  server: SERVER_EXTRA,
  synology_nas: NAS_EXTRA,
  core_switch: CORE_EXTRA,
  access_switch: ACCESS_EXTRA,
};

/** 每类设备的页签定义；未知 device_type 只保留通用页签。 */
export function deviceTabsFor(deviceType: string): DeviceTabDef[] {
  const overviewIds = OVERVIEW_MON_REQUIREMENTS[deviceType] ?? [];
  const tabs: DeviceTabDef[] = [
    {
      id: 'overview',
      title: '概览',
      sections: [{ kind: 'overview', requirementIds: overviewIds }],
    },
    {
      id: 'metrics',
      title: '指标',
      sections: [{ kind: 'metric-groups', requirementIds: monitoringRequirementIds(deviceType) }],
    },
    { id: 'components', title: '组件', sections: [{ kind: 'components' }] },
    { id: 'events', title: '事件', sections: [{ kind: 'events' }] },
    { id: 'collection-runs', title: '采集', sections: [{ kind: 'collection-runs' }] },
    { id: 'operations', title: '操作', sections: [{ kind: 'operations' }] },
  ];
  tabs.push(...(EXTRA_BY_TYPE[deviceType] ?? []));
  return tabs;
}
