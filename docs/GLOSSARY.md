# Warden 统一术语表

状态：`APPROVED_BASELINE`

后续需求、代码、API、数据库、界面、日志和测试必须使用本表语义。新增或修改术语需要 ADR。

| 中文 | 英文/代码 | 唯一定义 |
| --- | --- | --- |
| 设备 | device | Warden 直接连接和监控的一个物理硬件管理对象，不包含机房、机柜或业务系统 |
| 设备类别 | device_type | server、synology_nas、core_switch、access_switch 四种之一 |
| 管理地址 | management_endpoint | 用于访问设备管理面的主机/IP 与受控端口，不是通用 URL 抓取目标 |
| 适配器 | adapter | 将某类厂商协议映射成 Warden 统一能力的代码模块 |
| 能力 | capability | 一个稳定的可观察或可执行语义；状态来自设备发现 |
| 能力键 | capability_key | 统一英文标识，如 `power.cycle`；没有需求编号绑定的操作能力不得暴露 |
| 指标 | metric | 带时间、单位、质量和可选组件范围的观测值 |
| 组件 | component | 设备中的磁盘、风扇、电源、端口、光模块等被发现对象 |
| 设备事件 | device_event | 由 SEL、DSM 日志、Trap、Syslog 或轮询得到的时间点事实 |
| 告警 | alert | 平台根据当前设备事实自动生成的未恢复/已恢复问题，不是工单 |
| 可达性 | reachability | 平台能否连接设备管理面：unknown/online/offline |
| 综合健康 | health | 最近已知硬件健康：unknown/healthy/warning/critical；与可达性分离 |
| 数据新鲜度 | freshness | 受支持指标相对采集周期的新旧程度：unknown/fresh/stale/expired；不支持属于另一维度 |
| 就绪状态 | readiness | 设备配置是否可采集：not_ready/ready/misconfigured |
| 操作 | operation | 飞书原始需求允许的人为硬件动作或即时查询 |
| 操作预览 | operation_preview | 服务端对目标、参数、风险、步骤和影响的不可执行计划 |
| 操作任务 | operation_task | 用户确认后持久化并由 Worker 执行的唯一设备操作实例 |
| 结果待核验 | verification_required | 设备可能已执行但平台无法确定最终结果；不等同失败，也不可自动重试 |
| 启动描述符 | launch_descriptor | 用于打开厂商 KVM/DSM/Web 页面或终端的短期受控信息，不含密码 |
| 采集批次 | collection_run | 一台设备一次计划读取的生命周期和结果 |
| 当前态 | current state | 最近一次可信观测到的组件/设备状态 |
| 期望态 | desired state | 某次操作希望设备达到的状态，只存在于操作计划/验证中 |
| 支持状态 | support_state | 能力的固有状态：supported/unsupported/not_configured；正式支持还需真机认证 |
| 不支持 | unsupported | 设备/固件明确没有该能力，不代表平台执行成功 |
| 未配置 | not_configured | 设备可能支持，但平台缺少协议、许可、目标或必要配置 |
| 当前可用性 | runtime_availability | available/temporarily_unavailable；由离线、维护模式、权限外的运行条件和互斥任务动态计算，不覆盖支持状态 |
| 成功 | succeeded | 操作已得到设备明确成功并在可验证时完成回读验证 |
| 失败 | failed | 设备或平台明确知道操作未达到期望结果 |
| 超时 | timed_out | 已确认没有继续执行证据且超过计划时限；不确定时使用结果待核验 |
| 审计 | audit | 记录谁、何时、从哪里、对哪个对象、做什么以及结果；不记录秘密 |
| 真机认证 | hardware certification | 在目标型号/固件上对需求进行的可复核验收，不由模拟器替代 |

## 禁止的歧义表达

- 不用“设备状态”单独表示可达性和健康；必须说明维度。
- 不用“异常”作为错误码；必须使用稳定错误分类。
- 不用“执行成功”表示“请求已入队”；入队状态是 `queued`。
- 不用“失败”表示无法确认结果；使用 `verification_required`。
- 不用“支持”表示页面有按钮；需要能力发现和真机认证。
- 不用“实时”暗示毫秒级；监控更新目标以 `PROJECT_SPEC.md` 的 2 分钟为准。
- 不用“资产管理”指代通用 CMDB；本项目只查询设备自身序列号/FRU 等原始要求信息。
- 不用“通知”指代邮件/短信等外部通知；SSE 是界面状态更新机制。
