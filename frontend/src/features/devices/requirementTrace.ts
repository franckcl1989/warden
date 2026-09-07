/**
 * 需求-界面信息架构追踪表（M6T3 追踪收口，T-{REQ} 前端静态引用登记）。
 *
 * TRACEABILITY.md 要求每条需求的自动化测试 ID 在代码中有对应实现面。监控
 * （*-MON-*）需求由 deviceTabs.ts 的 requirementIds 静态声明页签归属并驱动
 * OverviewPanel/MetricGroupsPanel/PortsPanel/PoePanel/EventsPanel；操作
 * （*-ACT-*）需求的能力行由设备 capabilities API 下发（CapabilityButton 按
 * requirement_id 分组动态渲染，OperationsPanel/LaunchConsoleDialog），
 * 0.1.0 不做第二份静态操作清单（动态行即设备发现的真实能力，静态重复会
 * 成为假数据源）。
 *
 * 本表为机器检查脚本 scripts/check-traceability.ps1 提供每条需求的静态
 * 引用与界面归属说明；requirementTrace.spec.ts 断言其键集合与生成的
 * REQUIREMENTS 注册表完全一致（新增/删除需求必须同步本表，否则前端测试
 * 失败）。
 */

/**
 * 51 条原始需求在界面上的承载面。值使用固定词汇：
 * 「概览」「温度与内存」「存储」「电源与风扇」「端口」「光模块」「PoE」
 * 「二层与日志」「磁盘」「任务与日志」「事件页签」「操作页签（动态能力行）」
 * 「操作页签（launch 一次性票据）」「备份状态视图」。
 * 动态能力行 = 数据来自 capabilities API，需求编号在运行时渲染。
 */
export const REQUIREMENT_UI_SURFACES: Record<string, string> = {
  'SRV-MON-01': '服务器-概览（综合健康与告警灯摘要）',
  'SRV-MON-02': '服务器-概览与温度与内存页签',
  'SRV-MON-03': '服务器-温度与内存页签',
  'SRV-MON-04': '服务器-存储页签',
  'SRV-MON-05': '服务器-电源与风扇页签',
  'SRV-MON-06': '服务器-电源与风扇页签',
  'SRV-MON-07': '服务器-概览（入侵与告警灯摘要）',
  'SRV-MON-08': '服务器-事件页签（SEL 事件行动态）',
  'SRV-ACT-01': '服务器-操作页签（动态能力行）',
  'SRV-ACT-02': '服务器-操作页签（动态能力行）',
  'SRV-ACT-03': '服务器-操作页签（launch 一次性票据，KVM 控制台）',
  'SRV-ACT-04': '服务器-操作页签与文件页（动态能力行）',
  'SRV-ACT-05': '服务器-操作页签与文件页（动态能力行）',
  'SRV-ACT-06': '服务器-概览与操作页签与文件页（动态能力行）',
  'SRV-ACT-07': '服务器-概览（资产信息，动态能力行）',
  'NAS-MON-01': 'NAS-磁盘页签',
  'NAS-MON-02': 'NAS-存储页签',
  'NAS-MON-03': 'NAS-概览（温度、风扇与电源摘要）',
  'NAS-MON-04': 'NAS-存储页签',
  'NAS-MON-05': 'NAS-概览（UPS 联动状态）',
  'NAS-MON-06': 'NAS-概览与任务与日志页签（系统日志事件）',
  'NAS-ACT-01': 'NAS-操作页签（动态能力行）',
  'NAS-ACT-02': 'NAS-操作页签（launch 一次性票据，DSM 控制台）',
  'NAS-ACT-03': 'NAS-操作页签与文件页（动态能力行）',
  'NAS-ACT-04': 'NAS-磁盘页与操作页签（动态能力行）',
  'NAS-ACT-05': 'NAS-任务与日志页签-备份状态视图（BackupStatusPanel）',
  'NAS-ACT-06': 'NAS-操作页签与文件页（动态能力行）',
  'CORE-MON-01': '核心交换机-概览',
  'CORE-MON-02': '核心交换机-端口页签',
  'CORE-MON-03': '核心交换机-光模块页签',
  'CORE-MON-04': '核心交换机-概览（电源、风扇与温度）',
  'CORE-MON-05': '核心交换机-二层与日志页签',
  'CORE-MON-06': '核心交换机-二层与日志页签（端口震荡/重启/认证失败事件）',
  'CORE-ACT-01': '核心交换机-操作页签（动态能力行）',
  'CORE-ACT-02': '核心交换机-端口页与操作页签（动态能力行）',
  'CORE-ACT-03': '核心交换机-操作页签（launch 一次性票据，SSH/Telnet/Web）',
  'CORE-ACT-04': '核心交换机-操作页签与文件页（动态能力行）',
  'CORE-ACT-05': '核心交换机-操作页签与文件页（动态能力行）',
  'CORE-ACT-06': '核心交换机-光模块页与操作页签（动态能力行）',
  'CORE-ACT-07': '核心交换机-操作页签与文件页（动态能力行）',
  'ACCESS-MON-01': '接入交换机-概览',
  'ACCESS-MON-02': '接入交换机-端口页签',
  'ACCESS-MON-03': '接入交换机-PoE 页签',
  'ACCESS-MON-04': '接入交换机-概览（电源、风扇与温度）',
  'ACCESS-MON-05': '接入交换机-光模块页签',
  'ACCESS-ACT-01': '接入交换机-操作页签（动态能力行）',
  'ACCESS-ACT-02': '接入交换机-端口页与操作页签（动态能力行）',
  'ACCESS-ACT-03': '接入交换机-PoE 页与操作页签（动态能力行）',
  'ACCESS-ACT-04': '接入交换机-操作页签（launch 一次性票据，SSH/Web）',
  'ACCESS-ACT-05': '接入交换机-操作页签与文件页（动态能力行）',
  'ACCESS-ACT-06': '接入交换机-操作页签与文件页（动态能力行）',
};
