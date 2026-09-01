# Warden 0.1.0 设备适配设计

状态：`APPROVED_BASELINE`

## 1. 适配原则

- 平台能力以 `PROJECT_SPEC.md` 的 51 条需求为边界；
- API、页面和任务只认识统一能力键，不认识厂商命令；
- 标准协议优先，厂商 OEM 扩展只补标准协议缺口；
- “设备不支持”“当前未配置”“暂时不可用”“执行失败”是四种不同结果；
- 适配器不得吞掉错误或返回虚假空数据；
- 变更操作必须声明风险、互斥范围、超时、是否可验证和是否允许取消。
- 指标、事件和动作 profile 必须逐项实现 `contracts/metrics.json`、`contracts/events.json`、`contracts/operations.json`；适配器无权改变参数 schema、风险或成功条件。

## 2. 统一接口

后端领域层定义以下协议，具体实现位于 `backend/app/adapters/`：

```python
class DeviceAdapter(Protocol):
    adapter_key: str

    def probe(self, profile: ConnectionProfile) -> ProbeResult: ...
    def discover(self, session: DeviceSession) -> DiscoveryResult: ...
    def collect(self, session: DeviceSession, request: CollectionRequest) -> ObservationBatch: ...
    def plan_operation(self, snapshot: DeviceSnapshot, request: OperationRequest) -> OperationPlan: ...
    def preflight_operation(self, session: DeviceSession, plan: OperationPlan) -> PreflightResult: ...
    def execute_operation(self, session: DeviceSession, plan: OperationPlan, progress: ProgressSink) -> OperationResult: ...
    def verify_operation(self, session: DeviceSession, plan: OperationPlan, result: OperationResult) -> VerificationResult: ...
    def create_launch(self, session: DeviceSession, capability: str) -> LaunchDescriptor: ...
```

### 2.1 `ProbeResult`

分别返回网络、TLS/协议握手、认证和身份识别结果；不得用单个布尔值隐藏失败阶段。

### 2.2 `DiscoveryResult`

包含厂商、型号、序列号、固件版本、组件清单和固有支持状态：

- `supported`：适配器存在且发现设备支持；
- `unsupported`：设备/固件明确不支持；
- `not_configured`：需要额外协议、目标地址或许可。

离线、设备忙、维护模式和互斥任务属于 API 动态计算的 `runtime_availability=temporarily_unavailable`，不得回写覆盖固有支持状态，避免设备离线时整张能力表抖动。

### 2.3 `ObservationBatch`

每个成功观测值包含：`metric_key`、组件标识、值、规范单位、采集时间、质量、来源协议和可选原始证据摘要。质量为 `good`、`partial`、`error`；`stale/expired` 由平台依据观测时间计算。失败或缺失写入独立 `ObservationError`，包含指标/事件键、组件、稳定错误码和阶段；`unsupported` 更新能力支持状态，不写空指标点。

### 2.4 `OperationPlan`

必须包含：需求编号、能力键、归一化参数、风险级别、设备影响、互斥键、预期步骤、总超时、验证方法和是否可能短暂失联。

`plan_operation` 只能读取数据库中的 `DeviceSnapshot`（设备版本、最近能力/组件/指标、文件元数据），不得建立网络连接；因此 API 可在 2 秒目标内生成预览。Worker 领取任务后调用 `preflight_operation` 做实时只读检查，例如设备身份、当前电源/端口状态、未保存配置、空间、包兼容和冲突作业。preflight 失败发生在 dispatch fence 前，不得调用设备变更动作；计划关键字段或设备版本变化则任务以 `validation_failed/preview_stale` 结束并要求重新预览。

## 3. 适配器注册表

| `adapter_key` | 对象 | 主协议 | 补充协议 |
| --- | --- | --- | --- |
| `server.dell_idrac` | Dell iDRAC | Redfish HTTPS | Dell OEM Redfish/管理页 |
| `server.inspur_ibmc` | 浪潮 iBMC | Redfish HTTPS | 浪潮 OEM API |
| `server.xfusion_ibmc` | 超聚变 xFusion iBMC | Redfish HTTPS | xFusion OEM API |
| `server.lenovo_xcc` | Lenovo XCC | Redfish HTTPS | Lenovo OEM API |
| `server.huawei_ibmc` | Huawei iBMC | Redfish HTTPS | Huawei OEM API |
| `nas.synology_dsm` | DS224+/DS225+ | DSM WebAPI HTTPS | SNMP、管理页 |
| `switch.huawei_vrp_core` | S5732-H48XUM2CC、S5731S-S48P4X-A | SNMPv3 + SSH | Syslog、Trap、Web、Telnet 连接 |
| `switch.huawei_vrp_access` | S5735-L48P4S-A1 | SNMPv3 + SSH | Syslog、Trap、Web |

自动识别结果只能推荐适配器，最终保存的 `adapter_key` 必须通过该适配器的身份校验。

## 4. 服务器适配

服务器统一以 Redfish 为主。Redfish 标准资源包括 Systems、Chassis、Managers、LogService、UpdateService 和 VirtualMedia；设计参考 DMTF 已发布 Schema Bundle 2026.1：<https://redfish.dmtf.org/schemas/DSP8010_2026.1.html>。适配器按设备实际 `@odata.type` 版本解析，不能要求旧管理卡实现最新 schema。

### 4.1 监控映射

| 需求 | 统一能力/指标 | Redfish/OEM 来源 |
| --- | --- | --- |
| `SRV-MON-01` | `health.overall`、`indicator.led` | ComputerSystem/Chassis Status、IndicatorLED/OEM |
| `SRV-MON-02` | `temperature.cpu`、`temperature.memory`、`temperature.inlet`、`temperature.board` | Thermal/ThermalSubsystem Sensors，按物理上下文分类 |
| `SRV-MON-03` | `memory.status`、`memory.ecc_errors` | Memory Status、Metrics/OEM |
| `SRV-MON-04` | `drive.status`、`drive.smart`、`raid.status`、`drive.predictive_failure` | Storage/Drives/Volumes/OEM |
| `SRV-MON-05` | `psu.present`、`psu.status`、`psu.load_w`、`psu.voltage_v` | Power/PowerSubsystem |
| `SRV-MON-06` | `fan.rpm`、`fan.status` | Thermal/Fans |
| `SRV-MON-07` | `chassis.intrusion`、`indicator.led` | Chassis PhysicalSecurity/IndicatorLED/OEM |
| `SRV-MON-08` | `event.sel` | Manager/System LogServices Entries |

Redfish 字段缺失时允许 OEM 补充；OEM 解析必须保存脱敏 fixture 做契约测试。

### 4.2 操作映射

| 需求 | 能力键 | 适配路径 |
| --- | --- | --- |
| `SRV-ACT-01` | `manager.reset` | Manager Reset action/OEM 冷复位；执行后等待管理口恢复 |
| `SRV-ACT-02` | `power.on`、`power.off`、`power.cycle` | ComputerSystem Reset action；`power.off` 只用 GracefulShutdown，不回退 ForceOff；`power.cycle` 统一承载原文强制重启并按认证 overlay 映射 ForceRestart/PowerCycle |
| `SRV-ACT-03` | `console.kvm.open` | 优先通过厂商 API 创建 HTML5 KVM 会话并返回启动描述符；无法创建会话时可打开明确的 KVM 入口页但不得注入密码 |
| `SRV-ACT-04` | `logs.support_bundle.collect` | OEM TSR/support dump；无 OEM 包时至少导出 SEL/系统日志并明确产物构成 |
| `SRV-ACT-05` | `virtual_media.mount`、`virtual_media.unmount` | VirtualMedia InsertMedia/EjectMedia 或 OEM；需设备可访问镜像 URL |
| `SRV-ACT-06` | `firmware.query`、`firmware.update` | UpdateService/OEM job；升级前检查目标和包元数据 |
| `SRV-ACT-07` | `asset.refresh` | Systems/Chassis/Managers/FRU 资源发现 |

固件、TSR 和 KVM 通常存在厂商差异；每个厂商建立独立 overlay，不在通用 Redfish 适配器中堆叠厂商条件分支。

KVM 正式认证要求点击 Warden 入口后能进入可用的远程控制台，最多允许厂商自身再次认证；仅打开通用管理首页且无法定位 KVM 不算 `SRV-ACT-03` 通过。

## 5. 群晖 NAS 适配

DSM 通过 HTTPS WebAPI 登录与调用；参考 Synology DSM Login Web API Guide：<https://global.download.synology.com/download/Document/Software/DeveloperGuide/Os/DSM/All/enu/DSM_Login_Web_API_Guide_enu.pdf>，监控 OID 参考官方 MIB Guide：<https://global.download.synology.com/download/Document/Software/DeveloperGuide/Firmware/DSM/All/enu/Synology_DiskStation_MIB_Guide.pdf>。SNMP 用于补充监控，不用 SNMP SET 执行变更。

官方登录指南只证明 API 发现/认证流程，不证明 Storage、SMART、Support、Update 或 Control Panel 方法稳定公开。每个非公开管理 API 必须标记 `vendor_private`，以目标 DSM 版本的 API discovery、脱敏请求/响应 fixture 和真机行为形成认证证据；不得仅凭网络抓包猜参数后宣称通用支持。官方 MIB 指南与现场 SNMPv3 可用性不一致时以真机认证为准；不得为了取到指标静默降级 SNMPv2c。

### 5.1 监控映射

| 需求 | 统一能力/指标 | 来源 |
| --- | --- | --- |
| `NAS-MON-01` | `disk.status`、`disk.smart`、`disk.bad_sectors` | DSM Storage API/SNMP |
| `NAS-MON-02` | `storage_pool.status`、`raid.status`、`raid.rebuild_progress` | DSM Storage API |
| `NAS-MON-03` | `temperature.system`、`fan.status/rpm`、`psu.status` | DSM System API/SNMP |
| `NAS-MON-04` | `volume.usage_percent`、`shared_folder.usage_percent` | DSM Storage/File API；使用率必须由已用量/配额或容量计算，缺少分母时不以字节数冒充百分比 |
| `NAS-MON-05` | `ups.status` | DSM UPS API/SNMP |
| `NAS-MON-06` | `event.system_log`、`connectivity.management` | DSM Log API + HTTPS 探测 |

### 5.2 操作映射

| 需求 | 能力键 | 适配路径 |
| --- | --- | --- |
| `NAS-ACT-01` | `power.restart`、`power.shutdown` | DSM System API，关机后允许连接预期中断 |
| `NAS-ACT-02` | `console.dsm.open` | 返回 DSM HTTPS 地址，不注入密码 |
| `NAS-ACT-03` | `logs.support_bundle.collect` | DSM Log/Support API，产物进入受控文件存储 |
| `NAS-ACT-04` | `disk.smart_test.quick`、`disk.smart_test.full` | DSM Storage API；按磁盘互斥并跟踪异步进度 |
| `NAS-ACT-05` | `backup.status.refresh` | DSM Snapshot/Backup 相关 API，只读刷新 |
| `NAS-ACT-06` | `firmware.update`、`snmp.configure` | DSM Update/Control Panel API；配置 Trap 目标为平台接收器 |

DSM API 受版本和套件影响。发现阶段必须记录 API 名称和版本；缺失时返回 `unsupported`，不能猜测 URL。

## 6. 华为交换机适配

监控优先 SNMPv3，配置与诊断使用 SSH/VRP CLI，事件使用 Syslog 和 SNMP Trap。华为企业支持资料入口提供 Command、Log、MIB 和 YANG 参考：<https://info.support.huawei.com/enterprise/en/switches/cloudengine-s5735-l-pid-252506931>。实现不能把一个型号页面当成三个型号的共同证明；每份认证记录必须归档与精确型号/VRP 版本匹配的文档编号、MIB 包散列和命令参考版本。

### 6.1 连接规则

- SNMPv3 为默认；允许管理员显式选择 SNMPv2c，界面持续显示弱安全警告；
- 自动化命令只走 SSH，不使用 Telnet；
- Telnet 仅用于 `CORE-ACT-03` 的人工远程连接，默认禁用；
- Web 网管只返回 HTTPS/HTTP 启动地址；
- 首次发现执行 `display version`、设备型号和 VRP 版本校验，并选择匹配命令模板。

### 6.2 核心交换机监控

| 需求 | 统一能力/指标 | 来源 |
| --- | --- | --- |
| `CORE-MON-01` | `system.cpu_percent`、`system.memory_percent` | Huawei MIB/SNMP |
| `CORE-MON-02` | `interface.admin_status`、`interface.oper_status`、`interface.in_bps`、`interface.out_bps`、`interface.crc_errors`、`interface.errors`、`interface.drops` | IF-MIB/Huawei MIB；基于 64 位计数器计算速率 |
| `CORE-MON-03` | `transceiver.rx_dbm`、`transceiver.tx_dbm`、`transceiver.temperature_c`、`transceiver.voltage_v`、`transceiver.current_ma` | Huawei 光模块 MIB/必要时只读 CLI |
| `CORE-MON-04` | `psu.*`、`fan.*`、`temperature.system` | ENTITY-SENSOR/Huawei MIB |
| `CORE-MON-05` | `loop.status`、`broadcast_storm.status`、`stp.port_state` | Huawei/STP MIB + 事件 |
| `CORE-MON-06` | `event.port_flap`、`event.device_restart`、`event.auth_failure` | Syslog/Trap，轮询日志兜底 |

### 6.3 核心交换机操作

| 需求 | 能力键 | 适配路径 |
| --- | --- | --- |
| `CORE-ACT-01` | `device.restart` | SSH 执行保存提示策略明确的重启命令；回连验证 |
| `CORE-ACT-02` | `interface.admin.set` | SSH 进入目标接口执行 shutdown/undo shutdown；回读状态 |
| `CORE-ACT-03` | `console.ssh.open`、`console.telnet.open`、`console.web.open` | 浏览器终端或 Web 启动描述符 |
| `CORE-ACT-04` | `logs.diagnostic.collect` | SSH 执行 `display diagnostic-information`，流式写入文件 |
| `CORE-ACT-05` | `config.backup`、`config.restore` | SSH/SFTP；备份后校验，恢复前预览并限制设备型号/版本 |
| `CORE-ACT-06` | `transceiver.diagnose` | SNMP/只读 CLI 即时查询 |
| `CORE-ACT-07` | `firmware.update` | SFTP/设备文件传输 + SSH 升级流程；校验空间、版本和哈希 |

重启发现未保存配置时必须阻断，平台不擅自保存。配置恢复只能使用认证矩阵记录的单一策略，不能在运行时猜“合并/替换、当前/启动配置、是否重启”。具体前置条件和成功判定见 `contracts/operations.json`。

### 6.4 接入交换机监控与操作

| 需求 | 能力键 | 适配路径 |
| --- | --- | --- |
| `ACCESS-MON-01` | `system.cpu_percent`、`system.memory_percent` | SNMP |
| `ACCESS-MON-02` | `interface.admin_status`、`interface.oper_status`、`interface.in_bps`、`interface.out_bps`、`interface.errors` | SNMP |
| `ACCESS-MON-03` | `poe.port.status`、`poe.port.power_w`、`poe.total_power_w`、`poe.power_budget_w`、`poe.total_power_percent`、`poe.total_power_alarm` | Huawei PoE MIB；告警取设备状态或由总功耗/设备预算计算，分母未知时不得伪造百分比/正常状态 |
| `ACCESS-MON-04` | `psu.*`、`fan.*`、`temperature.system` | SNMP |
| `ACCESS-MON-05` | `transceiver.rx_dbm`、`transceiver.tx_dbm` | 上联端口 MIB/只读 CLI |
| `ACCESS-ACT-01` | `device.restart` | SSH + 回连验证 |
| `ACCESS-ACT-02` | `interface.admin.set` | SSH + 状态回读 |
| `ACCESS-ACT-03` | `poe.port.set` | SSH 对目标端口 PoE 供电开关 + 回读 |
| `ACCESS-ACT-04` | `console.ssh.open`、`console.web.open` | 浏览器终端/Web 描述符 |
| `ACCESS-ACT-05` | `logs.collect`、`config.backup`、`config.restore` | SSH/SFTP |
| `ACCESS-ACT-06` | `firmware.update` | SFTP + SSH 升级流程 |

## 7. 错误分类

适配器只能返回以下设备错误代码；它们必须是 `contracts/error-codes.json` 的子集。平台认证、并发和依赖错误由应用层产生，适配器不得伪造：

| 错误 | 含义 | 自动重试 |
| --- | --- | --- |
| `network_unreachable` | 无路由、拒绝连接或连接超时 | 读取可退避重试 |
| `tls_validation_failed` | 证书校验失败 | 否，需修改信任配置 |
| `authentication_failed` | 用户名/密码/Token/SNMP 认证失败 | 否 |
| `permission_denied_by_device` | 设备账号权限不足 | 否 |
| `protocol_error` | 响应格式或协议不符合预期 | 读取最多重试 1 次 |
| `unsupported_capability` | 设备/固件不支持 | 否 |
| `not_configured` | 缺少协议或外部目标配置 | 否 |
| `device_busy` | 设备已有冲突任务 | 按设备建议等待 |
| `validation_failed` | 参数、固件或配置不匹配 | 否 |
| `rate_limited` | 设备限制请求 | 按 Retry-After/退避 |
| `operation_failed` | 设备明确返回失败 | 否 |
| `ambiguous_result` | 连接中断且无法确认是否执行 | 禁止重放，进入待核验 |

异常文本可以附加，但 API 和测试以错误代码为准。

## 8. 重试和超时

- 读取连接：5 秒连接、30 秒请求；最多 2 次指数退避重试；
- SNMP：2 秒超时、2 次重试，批量 OID 限制可配置；
- 普通 SSH 命令：连接 10 秒、命令 60 秒；
- 诊断包：默认 30 分钟；
- 固件升级：默认 120 分钟，按驱动可覆盖；
- 重启/关机/BMC 复位：发出后不重发，通过离线和回连验证；
- 所有超时值记录在 `OperationPlan` 和任务审计中。
- 以上是协议默认值；具体人工动作的总超时、前置条件、断连预期和验证只取 `contracts/operations.json` profile，文档冲突时停止实现并记录 ADR。

## 9. 副作用调用防重放

Worker 在真正调用设备前，必须在 PostgreSQL 提交 `dispatch_started_at`、适配器版本、规范参数散列和计划散列。只有该事务成功后才允许发出设备请求。Worker 崩溃后：

- 没有 `dispatch_started_at`：任务可以重新领取但仍需重新检查全部前置条件；
- 已有 `dispatch_started_at` 且 profile `side_effect=true`：恢复器只能调用 `verify_operation`；不能再次调用 `execute_operation`；
- profile `side_effect=false`：可以创建新 attempt 重试只读调用；已有 `device_job_id` 时只能查询原 job，不能再创建；残缺临时文件不得转为 ready；
- 无法证明成功或失败：进入 `verification_required`；
- 厂商返回可持久查询的 job ID：先落库 job ID，再通过查询推进，不重新创建 job。

该 fence 不能从数学上保证设备端 exactly-once，但能保证平台不会把不确定动作当成可重试消息。

## 10. 适配器认证门禁

每个目标厂商/型号/主固件版本必须维护认证记录：

- 设备身份和固件；
- 支持/不支持的能力键及证据；
- 脱敏响应/CLI fixture；
- 监控值与设备原生界面对照；
- 每个有副作用操作的前置状态、执行结果和回读证据；
- 已知限制与安全注意事项。

没有真机证据的驱动只能标记 `experimental`，不能作为 0.1.0 正式支持完成项。
