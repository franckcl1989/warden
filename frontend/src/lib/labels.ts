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

/**
 * 适配器展示名；fake.simple 明确标注开发用，绝不冒充真实硬件支持。
 * 五个厂商管理卡适配器（server.*，M3T5）统一标注“真机认证待完成”：
 * 平台能力状态与认证矩阵（hardware-targets.json / HARDWARE_CERTIFICATION.md）
 * 才是正式支持依据，界面文案不得声称已通过真机认证。
 */
export const ADAPTER_LABELS: Record<string, string> = {
  'fake.simple': '测试适配器（开发用）',
  'server.dell_idrac': 'Dell iDRAC（真机认证待完成）',
  'server.inspur_ibmc': 'Inspur iBMC（真机认证待完成）',
  'server.xfusion_ibmc': 'xFusion iBMC（真机认证待完成）',
  'server.lenovo_xcc': 'Lenovo XCC（真机认证待完成）',
  'server.huawei_ibmc': 'Huawei iBMC（真机认证待完成）',
};

/** 事件严重级别（GLOSSARY/contracts：unknown/info/warning/critical）。 */
export const EVENT_SEVERITY_LABELS: Record<string, string> = {
  unknown: '未知',
  info: '信息',
  warning: '警告',
  critical: '严重',
};

/** 当前问题状态（PRODUCT_DESIGN §6.4：active/resolved）。 */
export const ALERT_STATUS_LABELS: Record<string, string> = {
  active: '未恢复',
  resolved: '已恢复',
};

/** 当前问题严重级别（监控引擎只产生 critical/warning，未知值原样显示）。 */
export const ALERT_SEVERITY_LABELS: Record<string, string> = {
  critical: '严重',
  warning: '警告',
};

/** 操作任务状态（GLOSSARY/operations.json：8 态，禁止歧义合并）。 */
export const OPERATION_STATE_LABELS: Record<string, string> = {
  queued: '已排队',
  running: '执行中',
  waiting_device: '等待设备',
  succeeded: '成功',
  failed: '失败',
  timed_out: '超时',
  cancelled: '已取消',
  verification_required: '结果待核验',
};

/** 操作风险等级（PRODUCT_DESIGN §7.2 / operations.json）。 */
export const OPERATION_RISK_LABELS: Record<string, string> = {
  low: '低风险',
  medium: '中风险',
  high: '高风险',
};

/** 数据新鲜度（PRODUCT_DESIGN §6.3：unknown/fresh/stale/expired）。 */
export const FRESHNESS_LABELS: Record<string, string> = {
  unknown: '尚无观测',
  fresh: '正常',
  stale: '即将过期',
  expired: '已过期',
};

/** 观测质量（metrics API：good/partial）。 */
export const QUALITY_LABELS: Record<string, string> = {
  good: '完整',
  partial: '部分缺失',
};

/** 采集类型（collection.py：metrics/logs/discovery）。 */
export const COLLECTION_TYPE_LABELS: Record<string, string> = {
  metrics: '指标采集',
  logs: '日志采集',
  discovery: '发现采集',
};

/** 采集批次状态（collection.py：scheduled/running/succeeded/partial/failed）。 */
export const COLLECTION_STATE_LABELS: Record<string, string> = {
  scheduled: '已计划',
  running: '采集中',
  succeeded: '成功',
  partial: '部分成功',
  failed: '失败',
};

/** 文件类型（API_CONTRACT §8 / PRODUCT_DESIGN §8）。 */
export const FILE_TYPE_LABELS: Record<string, string> = {
  firmware: '固件',
  virtual_media: '虚拟介质',
  support_bundle: '支持报告',
  config_backup: '配置备份',
  operation_log: '操作日志',
};

/** 文件状态（files API：uploading/ready/quarantined/deleted）。 */
export const FILE_STATUS_LABELS: Record<string, string> = {
  uploading: '上传中',
  ready: '就绪',
  quarantined: '已隔离',
  deleted: '已删除',
};

/** 序列实际分辨率展示（UI_SPEC §7.3：界面显示实际分辨率）。 */
export const RESOLUTION_LABELS: Record<string, string> = {
  raw: '原始点',
  '5m': '5 分钟聚合',
  '1h': '1 小时聚合',
};

/** 人工核验结论（resolve-verification：succeeded/failed）。 */
export const RESOLVE_OUTCOME_LABELS: Record<string, string> = {
  succeeded: '标记为成功',
  failed: '标记为失败',
};

/** 人工核验证据类型（operations 路由白名单）。 */
export const RESOLVE_EVIDENCE_LABELS: Record<string, string> = {
  device_ui: '设备界面',
  device_cli: '设备命令行',
  device_log: '设备日志',
  task_record: '任务记录',
  other: '其他',
};

/** 组件支持状态禁用时悬停展示的固定原因文案（UI_SPEC §8）。 */
export const CAPABILITY_REASON_HINTS: Record<string, string> = {
  unsupported: '设备或固件不支持该能力',
  not_configured: '缺少协议、凭据、许可或必要配置',
};

/**
 * 枚举/状态指标值的可安全直译子集（按值翻译在多组枚举里语义一致时才收录；
 * up/down/testing 等按上下文含义不同、界面直接原样展示代码值，避免歧义文案）。
 */
export const ENUM_VALUE_LABELS: Record<string, string> = {
  unknown: '未知',
  healthy: '健康',
  warning: '警告',
  critical: '严重',
  ok: '正常',
  normal: '正常',
  optimal: '正常',
  degraded: '降级',
  rebuilding: '重建中',
  failed: '故障',
  passed: '通过',
  present: '在位',
  absent: '不在位',
  detected: '已检测',
  off: '关闭',
  on: '开启',
  identify: '定位中',
  running: '运行中',
  fault: '故障',
  denied: '拒绝',
  on_battery: '电池供电',
  low_battery: '电池电量低',
  communication_lost: '通信丢失',
  forwarding: '转发',
  discarding: '丢弃',
  learning: '学习',
  broken: '故障',
};

/** 指标键的中文说明（chart 标题/选择器用）。键全部来自 contracts/metrics.json。 */
export const METRIC_KEY_LABELS: Record<string, string> = {
  'health.overall': '综合健康',
  'indicator.led': '面板告警灯',
  'chassis.intrusion': '机箱入侵',
  'temperature.cpu': 'CPU 温度',
  'temperature.memory': '内存温度',
  'temperature.inlet': '进风口温度',
  'temperature.board': '主板温度',
  'temperature.system': '系统温度',
  'memory.status': '内存条状态',
  'memory.ecc_errors': 'ECC 错误计数',
  'drive.status': '硬盘状态',
  'drive.smart': '硬盘 S.M.A.R.T',
  'drive.predictive_failure': '硬盘预测故障',
  'disk.status': '磁盘状态',
  'disk.smart': '磁盘 S.M.A.R.T',
  'disk.bad_sectors': '坏扇区',
  'raid.status': 'RAID 状态',
  'raid.rebuild_progress': 'RAID 重建进度',
  'storage_pool.status': '存储池状态',
  'volume.usage_percent': '卷使用率',
  'shared_folder.usage_percent': '共享文件夹使用率',
  'psu.present': '电源在位',
  'psu.status': '电源状态',
  'psu.load_w': '电源负载',
  'psu.voltage_v': '电源电压',
  'fan.rpm': '风扇转速',
  'fan.status': '风扇状态',
  'ups.status': 'UPS 状态',
  'connectivity.management': '管理连通性',
  'system.cpu_percent': 'CPU 利用率',
  'system.memory_percent': '内存利用率',
  'interface.admin_status': '端口管理状态',
  'interface.oper_status': '端口运行状态',
  'interface.in_bps': '端口入向速率',
  'interface.out_bps': '端口出向速率',
  'interface.crc_errors': '端口 CRC 错误',
  'interface.errors': '端口错误',
  'interface.drops': '端口丢包',
  'transceiver.rx_dbm': '光模块接收功率',
  'transceiver.tx_dbm': '光模块发送功率',
  'transceiver.temperature_c': '光模块温度',
  'transceiver.voltage_v': '光模块电压',
  'transceiver.current_ma': '光模块电流',
  'loop.status': '环路检测',
  'broadcast_storm.status': '广播风暴',
  'stp.port_state': 'STP 端口状态',
  'poe.port.status': 'PoE 端口状态',
  'poe.port.power_w': 'PoE 端口功率',
  'poe.total_power_w': 'PoE 总功率',
  'poe.power_budget_w': 'PoE 功率预算',
  'poe.total_power_percent': 'PoE 总功率占比',
  'poe.total_power_alarm': 'PoE 总功率告警',
};

export function label(map: Record<string, string>, value: string | null | undefined): string {
  if (value === null || value === undefined) {
    return '—';
  }
  return map[value] ?? value;
}
