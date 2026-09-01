# Warden 0.1.0 端到端追踪矩阵

状态：`APPROVED_BASELINE`

## 1. 使用规则

本矩阵是 0.1.0 完整性的核对表。每行必须同时存在：

- 原始需求编号；
- 稳定能力键/指标键；
- 用户可见页面；
- API 路径或操作类型；
- 适配器方法；
- 自动化测试 ID；
- 发布前真机认证证据。

表中 `operation` 表示两阶段 `operation-previews` + `operations` API；`launch` 表示 `/launches`；`metrics` 表示 latest/series；`events` 表示设备事件 API。指标、事件和动作参数的机器定义分别以 `contracts/metrics.json`、`contracts/events.json` 和 `contracts/operations.json` 为准，表格不得自行补语义。

## 2. 服务器

### 2.1 监控

| 需求 | 能力/指标键 | 页面 | API | 适配器 | 测试 |
| --- | --- | --- | --- | --- | --- |
| `SRV-MON-01` | `health.overall`、`indicator.led` | 服务器/概览 | metrics | `collect(health)` | `T-SRV-MON-01` |
| `SRV-MON-02` | `temperature.cpu`、`temperature.memory`、`temperature.inlet`、`temperature.board` | 温度与内存 | metrics/series | `collect(thermal)` | `T-SRV-MON-02` |
| `SRV-MON-03` | `memory.status`、`memory.ecc_errors` | 温度与内存 | metrics/components | `collect(memory)` | `T-SRV-MON-03` |
| `SRV-MON-04` | `drive.status`、`drive.smart`、`raid.status`、`drive.predictive_failure` | 存储 | metrics/components | `collect(storage)` | `T-SRV-MON-04` |
| `SRV-MON-05` | `psu.present`、`psu.status`、`psu.load_w`、`psu.voltage_v` | 电源与风扇 | metrics/components | `collect(power)` | `T-SRV-MON-05` |
| `SRV-MON-06` | `fan.rpm`、`fan.status` | 电源与风扇 | metrics/series | `collect(thermal)` | `T-SRV-MON-06` |
| `SRV-MON-07` | `chassis.intrusion`、`indicator.led` | 概览 | metrics/events | `collect(chassis)` | `T-SRV-MON-07` |
| `SRV-MON-08` | `event.sel` | 事件 | events | `collect(logs)` | `T-SRV-MON-08` |

### 2.2 人工操作

| 需求 | 能力键 | 页面 | API | 适配器 | 测试 |
| --- | --- | --- | --- | --- | --- |
| `SRV-ACT-01` | `manager.reset` | 服务器/操作 | operation | `plan/preflight/execute/verify` | `T-SRV-ACT-01` |
| `SRV-ACT-02` | `power.on`、`power.off`、`power.cycle` | 服务器/操作 | operation | `plan/preflight/execute/verify` | `T-SRV-ACT-02` |
| `SRV-ACT-03` | `console.kvm.open` | 服务器/操作 | launch | `create_launch` | `T-SRV-ACT-03` |
| `SRV-ACT-04` | `logs.support_bundle.collect` | 服务器/操作、文件 | operation/files | `plan/preflight/execute/verify` | `T-SRV-ACT-04` |
| `SRV-ACT-05` | `virtual_media.mount`、`virtual_media.unmount` | 服务器/操作、文件 | operation | `plan/preflight/execute/verify` | `T-SRV-ACT-05` |
| `SRV-ACT-06` | `firmware.query`、`firmware.update` | 服务器/概览、操作、文件 | metrics + operation | `collect/plan/preflight/execute/verify` | `T-SRV-ACT-06` |
| `SRV-ACT-07` | `asset.refresh` | 服务器/概览 | operation + device | `plan/preflight/execute/verify` | `T-SRV-ACT-07` |

每个 `T-SRV-*` 在通用 Redfish 和 Dell/Inspur/xFusion/Lenovo/Huawei overlay 上执行；正式证据命名 `HC-SRV-{vendor}-{firmware}-{requirement}`。

## 3. 群晖 NAS

### 3.1 监控

| 需求 | 能力/指标键 | 页面 | API | 适配器 | 测试 |
| --- | --- | --- | --- | --- | --- |
| `NAS-MON-01` | `disk.smart`、`disk.bad_sectors`、`disk.status` | NAS/磁盘 | metrics/components | `collect(disks)` | `T-NAS-MON-01` |
| `NAS-MON-02` | `storage_pool.status`、`raid.status`、`raid.rebuild_progress` | NAS/存储 | metrics/components | `collect(storage)` | `T-NAS-MON-02` |
| `NAS-MON-03` | `temperature.system`、`fan.rpm`、`fan.status`、`psu.status` | NAS/概览 | metrics/series | `collect(system)` | `T-NAS-MON-03` |
| `NAS-MON-04` | `volume.usage_percent`、`shared_folder.usage_percent` | NAS/存储 | metrics/series | `collect(storage)` | `T-NAS-MON-04` |
| `NAS-MON-05` | `ups.status` | NAS/概览 | metrics | `collect(ups)` | `T-NAS-MON-05` |
| `NAS-MON-06` | `event.system_log`、`connectivity.management` | NAS/任务与日志、概览 | events/metrics | `collect(logs/connectivity)` | `T-NAS-MON-06` |

### 3.2 人工操作

| 需求 | 能力键 | 页面 | API | 适配器 | 测试 |
| --- | --- | --- | --- | --- | --- |
| `NAS-ACT-01` | `power.restart`、`power.shutdown` | NAS/操作 | operation | `plan/preflight/execute/verify` | `T-NAS-ACT-01` |
| `NAS-ACT-02` | `console.dsm.open` | NAS/操作 | launch | `create_launch` | `T-NAS-ACT-02` |
| `NAS-ACT-03` | `logs.support_bundle.collect` | NAS/操作、文件 | operation/files | `plan/preflight/execute/verify` | `T-NAS-ACT-03` |
| `NAS-ACT-04` | `disk.smart_test.quick`、`disk.smart_test.full` | NAS/磁盘、操作 | operation | `plan/preflight/execute/verify` | `T-NAS-ACT-04` |
| `NAS-ACT-05` | `backup.status.refresh` | NAS/任务与日志 | operation + metrics | `plan/preflight/execute/verify` | `T-NAS-ACT-05` |
| `NAS-ACT-06` | `firmware.update`、`snmp.configure` | NAS/操作、文件 | operation | `plan/preflight/execute/verify` | `T-NAS-ACT-06` |

真机证据命名 `HC-NAS-{DS224+|DS225+}-{DSM版本}-{requirement}`。

## 4. 核心交换机

### 4.1 监控

| 需求 | 能力/指标键 | 页面 | API | 适配器 | 测试 |
| --- | --- | --- | --- | --- | --- |
| `CORE-MON-01` | `system.cpu_percent`、`system.memory_percent` | 核心交换机/概览 | metrics/series | `collect(system)` | `T-CORE-MON-01` |
| `CORE-MON-02` | `interface.admin_status`、`interface.oper_status`、`interface.in_bps`、`interface.out_bps`、`interface.crc_errors`、`interface.errors`、`interface.drops` | 端口 | metrics/components | `collect(interfaces)` | `T-CORE-MON-02` |
| `CORE-MON-03` | `transceiver.rx_dbm`、`transceiver.tx_dbm`、`transceiver.temperature_c`、`transceiver.voltage_v`、`transceiver.current_ma` | 光模块 | metrics/series | `collect(transceivers)` | `T-CORE-MON-03` |
| `CORE-MON-04` | `psu.present`、`psu.status`、`fan.rpm`、`fan.status`、`temperature.system` | 概览 | metrics/components | `collect(hardware)` | `T-CORE-MON-04` |
| `CORE-MON-05` | `loop.status`、`broadcast_storm.status`、`stp.port_state` | 二层与日志 | metrics/events | `collect(layer2)` | `T-CORE-MON-05` |
| `CORE-MON-06` | `event.port_flap`、`event.device_restart`、`event.auth_failure` | 二层与日志 | events | `collect(logs)` + ingest | `T-CORE-MON-06` |

### 4.2 人工操作

| 需求 | 能力键 | 页面 | API | 适配器 | 测试 |
| --- | --- | --- | --- | --- | --- |
| `CORE-ACT-01` | `device.restart` | 核心交换机/操作 | operation | `plan/preflight/execute/verify` | `T-CORE-ACT-01` |
| `CORE-ACT-02` | `interface.admin.set` | 端口/操作 | operation | `plan/preflight/execute/verify` | `T-CORE-ACT-02` |
| `CORE-ACT-03` | `console.ssh.open`、`console.telnet.open`、`console.web.open` | 操作 | launch/terminal | `create_launch` | `T-CORE-ACT-03` |
| `CORE-ACT-04` | `logs.diagnostic.collect` | 操作、文件 | operation/files | `plan/preflight/execute/verify` | `T-CORE-ACT-04` |
| `CORE-ACT-05` | `config.backup`、`config.restore` | 操作、文件 | operation/files | `plan/preflight/execute/verify` | `T-CORE-ACT-05` |
| `CORE-ACT-06` | `transceiver.diagnose` | 光模块/操作 | operation + metrics | `plan/preflight/execute/verify` | `T-CORE-ACT-06` |
| `CORE-ACT-07` | `firmware.update` | 操作、文件 | operation | `plan/preflight/execute/verify` | `T-CORE-ACT-07` |

真机证据命名 `HC-CORE-{S5732-H48XUM2CC|S5731S-S48P4X-A}-{VRP版本}-{requirement}`。

## 5. 接入交换机

### 5.1 监控

| 需求 | 能力/指标键 | 页面 | API | 适配器 | 测试 |
| --- | --- | --- | --- | --- | --- |
| `ACCESS-MON-01` | `system.cpu_percent`、`system.memory_percent` | 接入交换机/概览 | metrics/series | `collect(system)` | `T-ACCESS-MON-01` |
| `ACCESS-MON-02` | `interface.admin_status`、`interface.oper_status`、`interface.in_bps`、`interface.out_bps`、`interface.errors` | 端口 | metrics/components | `collect(interfaces)` | `T-ACCESS-MON-02` |
| `ACCESS-MON-03` | `poe.port.status`、`poe.port.power_w`、`poe.total_power_w`、`poe.power_budget_w`、`poe.total_power_percent`、`poe.total_power_alarm` | PoE | metrics/components | `collect(poe)` | `T-ACCESS-MON-03` |
| `ACCESS-MON-04` | `psu.status`、`fan.rpm`、`fan.status`、`temperature.system` | 概览 | metrics/components | `collect(hardware)` | `T-ACCESS-MON-04` |
| `ACCESS-MON-05` | `transceiver.rx_dbm`、`transceiver.tx_dbm` | 光模块 | metrics/series | `collect(transceivers)` | `T-ACCESS-MON-05` |

### 5.2 人工操作

| 需求 | 能力键 | 页面 | API | 适配器 | 测试 |
| --- | --- | --- | --- | --- | --- |
| `ACCESS-ACT-01` | `device.restart` | 接入交换机/操作 | operation | `plan/preflight/execute/verify` | `T-ACCESS-ACT-01` |
| `ACCESS-ACT-02` | `interface.admin.set` | 端口/操作 | operation | `plan/preflight/execute/verify` | `T-ACCESS-ACT-02` |
| `ACCESS-ACT-03` | `poe.port.set` | PoE/操作 | operation | `plan/preflight/execute/verify` | `T-ACCESS-ACT-03` |
| `ACCESS-ACT-04` | `console.ssh.open`、`console.web.open` | 操作 | launch/terminal | `create_launch` | `T-ACCESS-ACT-04` |
| `ACCESS-ACT-05` | `logs.collect`、`config.backup`、`config.restore` | 日志与操作、文件 | operation/files | `plan/preflight/execute/verify` | `T-ACCESS-ACT-05` |
| `ACCESS-ACT-06` | `firmware.update` | 操作、文件 | operation | `plan/preflight/execute/verify` | `T-ACCESS-ACT-06` |

真机证据命名 `HC-ACCESS-S5735-L48P4S-A1-{VRP版本}-{requirement}`。

## 6. 必要平台支撑追踪

这些能力不是新增硬件业务操作，只承载原始矩阵。表中“边界”同样是契约：超出后必须新增用户批准的范围决策，不能继续沿用该 `PLT-*` 编号。

| 编号 | 支撑能力 | 为什么必需 | 设计/API/页面 | 边界 | 测试 |
| --- | --- | --- | --- | --- | --- |
| `PLT-01` | 本地认证与三类角色 | 防止未授权人员执行 `*-ACT-*` | SECURITY §2-3；auth/users/login | 不做组织、租户、设备级授权或身份平台 | `T-PLT-AUTH` |
| `PLT-02` | 设备接入与凭据 | 所有监控和操作都需要目标连接 | PRODUCT §4、SECURITY §5-7；device-probes/devices | 不做机房、机柜、CMDB、采购或库存 | `T-PLT-DEVICE` |
| `PLT-03` | 采集与状态语义 | 承载全部 `*-MON-*` | ARCHITECTURE §5、DATA §5；overview/metrics/events | 采集周期走部署配置，不做产品化采集设置页 | `T-PLT-COLLECT` |
| `PLT-04` | 当前问题展示 | 汇总源需求明确的当前故障/告警并防止旧数据冒充正常 | PRODUCT §6.4、DATA §6；alerts | 仅设备当前状态/告警、离线和过期；日志事件只留历史，不做自定义或无来源阈值 | `T-PLT-ALERT` |
| `PLT-05` | 操作任务与恢复 | 长时 `*-ACT-*` 必须可追踪且不重复执行 | DATA §7、API §6；operations | 不做定时、批量、编排或任意任务平台 | `T-PLT-OPERATION` |
| `PLT-06` | 受控文件 | 固件、ISO、配置和支持包需要输入/产物 | PRODUCT §8、SECURITY §9；files | 不做通用网盘或文档管理 | `T-PLT-FILE` |
| `PLT-07` | 操作审计 | 危险 `*-ACT-*` 必须可追责 | DATA §9、SECURITY §12；audit | 只追加脱敏记录；不做审计链头、签名或合规平台 | `T-PLT-AUDIT` |
| `PLT-08` | 私有部署与必要运行状态 | 无公网安装以及依赖故障时安全拒绝操作 | DEPLOYMENT；system/status、health、部署维护命令 | Web 只读；不做数据库备份、Prometheus 接口或通用运维控制台 | `T-PLT-DEPLOY` |
| `PLT-09` | 实时进度和终端 | 展示长任务进度并承载源需求中的远程连接 | ARCHITECTURE §5.3-5.4；SSE/WebSocket | 只发送实体变化和受控终端，不做消息中心 | `T-PLT-REALTIME` |

## 7. 发布核对

发布候选必须按 `HARDWARE_CERTIFICATION.md` 生成 `tests/hardware-certification/matrix.json`。覆盖单元不是一行需求摘要，而是 `target_id + requirement_id + capability_key`；当前契约动态计算为 306 个唯一记录。目标、字段和条件分别由 `contracts/hardware-targets.json` 与 `contracts/hardware-certification.schema.json` 定义。

允许状态：`not_started`、`automated_passed`、`hardware_passed`、`unsupported_with_evidence`、`failed`。0.1.0 严格发布门禁只接受 `hardware_passed`，或同时具有精确设备证据与用户书面接受引用的 `unsupported_with_evidence`。平台仍必须正确展示不支持状态，且不得把该记录宣传成已支持。

发布负责人执行：

```powershell
pwsh -File scripts/check-hardware-certification.ps1 -MatrixPath tests/hardware-certification/matrix.json -RequireReleaseReady
```
