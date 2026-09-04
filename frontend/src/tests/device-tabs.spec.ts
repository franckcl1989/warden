import { describe, expect, it } from 'vitest';

import {
  OVERVIEW_MON_REQUIREMENTS,
  deviceTabsFor,
  monitoringRequirementIds,
} from '@/features/devices/deviceTabs';

/**
 * 设备详情页签结构（PRODUCT_DESIGN §5.2-5.5）：四类设备都含通用页签组，
 * 并追加类型专属页签；需求 ID 由生成的 REQUIREMENTS 注册表推导。
 */
describe('设备详情页签配置（PRODUCT_DESIGN §5）', () => {
  it('四类设备都提供 概览/指标/组件/事件/采集/操作 通用页签', () => {
    for (const deviceType of ['server', 'synology_nas', 'core_switch', 'access_switch']) {
      const tabs = deviceTabsFor(deviceType);
      const ids = tabs.map((tab) => tab.id);
      for (const generic of [
        'overview',
        'metrics',
        'components',
        'events',
        'collection-runs',
        'operations',
      ]) {
        expect(ids, `${deviceType} 缺少通用页签 ${generic}`).toContain(generic);
      }
    }
  });

  it('服务器：温度与内存/存储/电源与风扇（PRODUCT_DESIGN §5.2）', () => {
    const tabs = deviceTabsFor('server');
    const titles = tabs.map((tab) => tab.title);
    expect(titles).toContain('温度与内存');
    expect(titles).toContain('存储');
    expect(titles).toContain('电源与风扇');
    const storage = tabs.find((tab) => tab.title === '存储');
    expect(storage?.sections.map((section) => section.kind)).toEqual([
      'components',
      'metric-groups',
    ]);
  });

  it('服务器概览承载 综合健康/温度摘要/资产与入侵 需求（PRODUCT_DESIGN §5.2）', () => {
    const overview = deviceTabsFor('server').find((tab) => tab.id === 'overview');
    const overviewIds = overview?.sections[0]?.requirementIds ?? [];
    expect(overviewIds).toContain('SRV-MON-01');
    expect(overviewIds).toContain('SRV-MON-02');
    expect(overviewIds).toContain('SRV-MON-07');
    expect(OVERVIEW_MON_REQUIREMENTS['server']).toEqual(expect.arrayContaining(overviewIds));
    // 概览页签承载的温度需求与「温度与内存」页签一致，避免页签归属漂移
    const tempMemory = deviceTabsFor('server').find((tab) => tab.id === 'temp-memory');
    expect(
      tempMemory?.sections.some((section) => section.requirementIds?.includes('SRV-MON-02')),
    ).toBe(true);
  });

  it('群晖 NAS：磁盘/存储/任务与日志（PRODUCT_DESIGN §5.3）', () => {
    const tabs = deviceTabsFor('synology_nas');
    const titles = tabs.map((tab) => tab.title);
    expect(titles).toContain('磁盘');
    expect(titles).toContain('存储');
    expect(titles).toContain('任务与日志');
  });

  it('群晖 NAS 类型专属页签承载 PRODUCT_DESIGN §5.3 需求归属', () => {
    const tabs = deviceTabsFor('synology_nas');
    const overview = tabs.find((tab) => tab.id === 'overview');
    expect(overview?.sections[0]?.requirementIds).toEqual([
      'NAS-MON-03',
      'NAS-MON-05',
      'NAS-MON-06',
    ]);

    const disks = tabs.find((tab) => tab.id === 'disks');
    expect(disks?.sections).toEqual([
      { kind: 'components', kinds: ['disk'] },
      { kind: 'metric-groups', requirementIds: ['NAS-MON-01'] },
    ]);

    const storage = tabs.find((tab) => tab.id === 'storage');
    expect(storage?.sections).toEqual([
      { kind: 'metric-groups', requirementIds: ['NAS-MON-02', 'NAS-MON-04'] },
    ]);

    const tasksLogs = tabs.find((tab) => tab.id === 'tasks-logs');
    // 备份/快照状态视图（NAS-ACT-05 刷新结果）与系统日志事件（NAS-MON-06）
    expect(tasksLogs?.sections).toEqual([
      { kind: 'backup-status' },
      { kind: 'events', eventTypes: ['event.system_log'] },
    ]);
  });

  it('核心交换机：端口/光模块使用端口表视图并承载 §5.4 需求映射（M5T5）', () => {
    const tabs = deviceTabsFor('core_switch');
    const titles = tabs.map((tab) => tab.title);
    expect(titles).toContain('端口');
    expect(titles).toContain('光模块');
    expect(titles).toContain('二层与日志');
    // PRODUCT_DESIGN §5.4 端口：管理/运行状态、流量、CRC、错误和丢包（CORE-MON-02）
    const ports = tabs.find((tab) => tab.id === 'ports');
    expect(ports?.sections).toEqual([
      { kind: 'ports', requirementIds: ['CORE-MON-02'], kinds: ['interface'] },
    ]);
    // §5.4 光模块：收发光功率、温度、电压和电流（CORE-MON-03）
    const transceivers = tabs.find((tab) => tab.id === 'transceivers');
    expect(transceivers?.sections).toEqual([
      { kind: 'ports', requirementIds: ['CORE-MON-03'], kinds: ['transceiver'] },
    ]);
    // §5.4 二层与日志：环路/广播风暴/STP（CORE-MON-05）+
    // 端口震荡/重启/认证失败事件（CORE-MON-06）
    const layer2 = tabs.find((tab) => tab.id === 'layer2-logs');
    expect(layer2?.sections).toEqual([
      { kind: 'metric-groups', requirementIds: ['CORE-MON-05'] },
      {
        kind: 'events',
        eventTypes: ['event.port_flap', 'event.device_restart', 'event.auth_failure'],
      },
    ]);
  });

  it('接入交换机：端口/PoE/光模块视图与 §5.5 需求映射（M5T5）', () => {
    const tabs = deviceTabsFor('access_switch');
    const titles = tabs.map((tab) => tab.title);
    expect(titles).toContain('端口');
    expect(titles).toContain('PoE');
    expect(titles).toContain('光模块');
    // §5.5 端口：状态、流量和错误（ACCESS-MON-02）
    const ports = tabs.find((tab) => tab.id === 'ports');
    expect(ports?.sections).toEqual([
      { kind: 'ports', requirementIds: ['ACCESS-MON-02'], kinds: ['interface'] },
    ]);
    // §5.5 PoE：端口供电、单端口功耗与总功耗（ACCESS-MON-03）——
    // 设备级摘要 + poe_port 行
    const poe = tabs.find((tab) => tab.id === 'poe');
    expect(poe?.sections).toEqual([
      { kind: 'poe', requirementIds: ['ACCESS-MON-03'], kinds: ['poe_port'] },
    ]);
    // §5.5 光模块：上联口光功率（ACCESS-MON-05）
    const transceivers = tabs.find((tab) => tab.id === 'transceivers');
    expect(transceivers?.sections).toEqual([
      { kind: 'ports', requirementIds: ['ACCESS-MON-05'], kinds: ['transceiver'] },
    ]);
  });

  it('监控需求 ID 从生成注册表按类型推导', () => {
    const server = monitoringRequirementIds('server');
    expect(server).toContain('SRV-MON-01');
    expect(server).toContain('SRV-MON-08');
    expect(server.some((id) => id.startsWith('NAS-'))).toBe(false);
    const nas = monitoringRequirementIds('synology_nas');
    expect(nas).toContain('NAS-MON-01');
    expect(nas).toContain('NAS-MON-06');
  });

  it('未知设备类型只保留通用页签', () => {
    const tabs = deviceTabsFor('unknown_device');
    expect(tabs.map((tab) => tab.id)).toEqual([
      'overview',
      'metrics',
      'components',
      'events',
      'collection-runs',
      'operations',
    ]);
  });
});
