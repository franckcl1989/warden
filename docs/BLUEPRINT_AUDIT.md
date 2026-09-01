# Warden 0.1.0 设计蓝图完成审计

状态：`APPROVED_BASELINE`  
审计日期：2026-09-01

## 1. 审计结论

0.1.0 已形成可执行、可追踪、可反证且经过范围收缩的设计基线，可以开始 M0 工程初始化。业务功能仅来自飞书 51 条硬件监控/操作；平台支撑均已说明必要性和禁止扩张边界。

本结论只批准设计，不代表代码、现场容量或任何真实硬件能力已完成。

## 2. 范围核对

| 检查 | 结论 |
| --- | --- |
| 核心目标 | 监控和管理一个小型私有化机房的硬件设备 |
| 业务来源 | 飞书原表是人工硬件功能唯一来源 |
| 原始数量 | 服务器 8+7、NAS 6+6、核心交换机 6+7、接入交换机 5+6，共 51 |
| 必要支撑 | 三类本地角色、设备接入、采集、当前问题、任务、文件、操作审计、部署状态、实时通道 |
| 明确排除 | 机房/机柜、组织/租户、CMDB、工单、通知、编排、通用规则、数据库备份、容量规划业务 |
| 支撑判定 | 必须证明缺少时会阻断来源需求；部署配置/内部实现不得包装为产品模块 |

源需求纠正保持为：只用 `power.cycle`；共享文件夹使用百分比；PoE 同时有瓦数、预算/信息性比例和设备告警状态；事件不写指标表。

## 3. 产品与工程闭环

| 层 | 固定内容与边界 |
| --- | --- |
| 产品/UI | 四类设备详情、来源监控/操作入口、当前问题、任务、必要文件、操作审计、用户和系统状态；无采集设置页 |
| 领域语义 | 支持状态、当前可用性、新鲜度、可达性、健康、问题和任务结果分离 |
| 设备适配 | 统一接口、标准协议优先、厂商 overlay、版本证据和明确失败语义 |
| 操作安全 | snapshot plan、live preflight、PostgreSQL 租约领取、dispatch fence、回读验证和待核验 |
| 数据 | 当前值、数值历史、状态变化、聚合、事件、任务、文件和只追加审计 |
| API | 50 个 REST/SSE/WS 白名单端点；无采集设置、维护切换和 Prometheus 端点 |
| 安全 | 本地三角色、会话/复验、CSRF、SSRF、凭据/文件加密和一次性票据 |
| 部署 | 单机 Compose、PostgreSQL 唯一权威、受控文件卷、离线交付和宿主机维护命令 |
| 验收 | 自动化层级、故障注入、现场负载、10 个目标和 306 条逐能力真机记录 |

## 4. 机器契约盘点

| 契约 | 数量/作用 |
| --- | --- |
| `capabilities.json` | 51 条源需求及能力白名单 |
| `metrics.json` | 52 个规范指标；无来源数值阈值均为 `alert_policy=none` |
| `events.json` | 5 个规范事件 |
| `operations.json` | 39 个精确动作 profile |
| `alert-rules.json` | 4 条当前问题规则，只覆盖设备当前状态/告警、离线和过期 |
| `http-api.json` | 50 个端点和稳定 operationId |
| `error-codes.json` | 27 个稳定错误和重试分类 |
| `hardware-targets.json` | 10 个真机目标 |
| `hardware-certification.schema.json` | 逐目标/需求/能力证据格式 |

代码注册表、OpenAPI、前端类型和测试数据必须从这些契约生成或校验，不得另建近似枚举。

## 5. 端到端追踪

```text
飞书原文
  -> SOURCE_BASELINE（散列绑定）
  -> PROJECT_SPEC（51 个稳定编号）
  -> capabilities + detailed contracts
  -> adapter collect/plan/preflight/execute/verify 或 launch
  -> HTTP operationId
  -> 页面/组件
  -> T-{requirement_id}
  -> target + requirement + capability 真机记录
```

平台支撑另由 `TRACEABILITY.md` 的必要性/边界表约束，不能把 `PLT-*` 当作无限扩展许可证。

## 6. 架构和容量边界

后台不使用 Redis、Celery 或消息 outbox。API 在 PostgreSQL 同事务创建任务与审计，Worker 用 `FOR UPDATE SKIP LOCKED`、租约和数据库互斥领取；操作调用前持久化 dispatch fence。一个 Worker 服务内分离采集与操作并发池。

不再承诺设计阶段虚构的固定设备数、活跃序列或磁盘容量。默认分层保留只用于控制增长；生产建议必须来自现场清单、实际发现序列和真实 schema 的验收压测。该过程是部署证据，不是容量规划产品能力。

PostgreSQL 和文件卷持久化，容器重建不得清空数据。数据库备份、PITR、灾备编排、RPO/RTO、审计散列链和独立链头均不属于 0.1.0。

## 7. 当前问题边界

`/alerts` 页面名称为“当前问题”，只显示设备明确的当前健康/故障/告警状态、离线和数据过期。设备日志/Trap/Syslog 只保留为事件历史。CPU/内存利用率、容量、错误计数、温度、功率、光功率和 PoE 比例只展示，不触发平台自造阈值。PoE 总功耗告警取 `poe.total_power_alarm`。

0.1.0 不提供规则编辑、确认、关闭、派单、通知或自动修复。

## 8. 真机真实性

设计不假设旧管理卡实现最新 Redfish，不把 Synology 登录指南当全部管理 API，不用一个 Huawei 型号资料证明其他型号，也不把模拟器、按钮或 HTTP/CLI 返回当真机完成。KVM 必须进入可交互控制台；unsupported、not_configured、超时和结果不明不得伪装成功。

正式发布必须生成实际 `tests/hardware-certification/matrix.json` 并通过严格门禁；设计阶段不创建占位矩阵。

## 9. 自动校验结果

执行：

```powershell
pwsh -File scripts/check-design.ps1
```

基线应输出：

```text
Design validation passed.
Source requirements: 51
Metric definitions: 52
Event definitions: 5
Operation profiles: 39
HTTP/SSE/WS endpoints: 50
Stable error codes: 27
Hardware targets: 10
Hardware certification records required: 306
Required files: 32
```

校验器还阻止无来源告警策略、被删除端点、Redis/Celery/outbox、固定容量常量和旧范围对象回流。严格真机校验当前因实际矩阵不存在而应失败，这是发布阻断而不是设计错误。

## 10. 开工与发布边界

可以开始：M0 仓库骨架、契约加载/生成、CI、PostgreSQL 数据/任务基础、错误和认证骨架。

不能宣称：某设备已支持、0.1.0 已完成、现场容量已达标或私有厂商 API 已可用。任何实现无法给出来源、真实适配路径、失败语义、API/UI 一致行为、自动化和必要真机证据时，不得标记完成。
