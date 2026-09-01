# Warden 人与 AI 开发执行手册

状态：`APPROVED_BASELINE`  
适用版本：0.1.0

## 1. 本手册解决什么问题

本手册把设计蓝图转换成可机械执行的工作流。参与者不需要依赖聊天记录或“理解作者意图”，但必须按本手册读取权威文件、选择契约、实现、验证并留下证据。

`APPROVED_BASELINE` 只表示设计被接受，不表示代码、适配器或真机能力已经完成。

## 2. 每次任务开始的固定动作

1. 阅读根目录 `AGENTS.md`。
2. 按其顺序阅读 `README`、原始需求快照、项目规格、追踪矩阵和所有机器契约。
3. 只读取与任务直接相关的专题文档，最后阅读 `DECISION_LOG.md`。
4. 运行 `pwsh -File scripts/check-design.ps1`；基线失败时先修复/报告基线，不能继续扩展实现。
5. 在任务描述中写明一个或多个 `SRV/NAS/CORE/ACCESS-*` 需求编号，或一个 `PLT-*` 支撑编号。
6. 检查工作区已有修改；不覆盖、不回滚、不顺手整理与任务无关的用户变更。

没有编号、无法确定编号或命中“停止条件”的任务，不开始写业务代码。

## 3. 权威来源与禁止猜测

发生矛盾时按以下顺序停下来核对：

1. 飞书原文；
2. `SOURCE_BASELINE.md` 的已复核快照；
3. `PROJECT_SPEC.md` 的 51 个工程编号；
4. `DECISION_LOG.md` 中最新 accepted 决策；
5. 机器契约；
6. `TRACEABILITY.md`；
7. 专题文档；
8. 代码、测试、任务描述和注释。

机器契约分工：

| 文件 | 唯一职责 | 禁止 |
| --- | --- | --- |
| `capabilities.json` | 需求到指标/事件/动作白名单 | 添加无需求编号的硬件动作 |
| `metrics.json` | 指标类型、单位、范围、聚合和告警策略 | 在适配器/UI 自定单位或把缺值写成 0 |
| `events.json` | 事件类型、来源和必需字段 | 把事件写入指标表 |
| `operations.json` | 动作参数、通道、风险、前置条件、超时和验证 | 前端/适配器另建近似 schema |
| `alert-rules.json` | 内置告警与阈值来源 | 发明通用规则编辑器或设备无依据阈值 |
| `http-api.json` | HTTP/SSE/WS 路径、方法、operationId 和支撑编号 | 新增未登记端点或手改前端 DTO |
| `error-codes.json` | 稳定错误、HTTP 映射、安全详情字段和重试分类 | 解析 message、返回厂商原文或自定重试 |
| `hardware-targets.json` | 0.1.0 真机目标、适配器边界和发布覆盖规则 | 用未登记型号或同系列设备外推正式支持 |
| `hardware-certification.schema.json` | 逐目标/需求/能力的证据字段和条件约束 | 用自由格式报告、截图或口头结论替代矩阵 |

无法从契约得到答案时，答案不是“合理猜一个”。应在 `DECISION_LOG.md` 增加 proposed ADR，标出冲突文件、受影响需求和安全后果，停止相关切片；不受影响的切片可以继续。

## 4. 任务分类闸门

### 4.1 原始硬件需求

必须绑定 51 个编号之一。可实现内容只包括该编号在能力白名单中的 metric/event/operation keys。拆分多个动作时，每个动作仍绑定同一来源编号，并有 `operations.json` profile。

### 4.2 必要平台支撑

只可使用 `TRACEABILITY.md` 第 6 节的 `PLT-*`：认证、设备接入、采集、当前问题、任务、文件、审计、部署运行和实时通道。使用前必须写明缺少该支撑会阻断的来源需求；部署配置或内部代码足以解决时不得增加产品页面/API。平台支撑不得借机新增机房、机柜、CMDB、工单、通知、自动化、数据库备份、通用告警规则或系统运维平台。

### 4.3 拒绝或改写任务

出现下列要求时，先拒绝实现并指出范围依据：

- 没有来源编号的设备命令、通用 CLI、批量/定时危险动作；
- 机房/机柜/U 位、组织/租户、通用资产、工单、外部通知；
- 用 placeholder、mock 成功或“先返回成功后补适配器”冒充能力；
- 为了让测试通过而降低权限、跳过复验/确认/审计/验证；
- 把 unsupported、not_configured、offline、expired、failed、verification_required 合并。

## 5. 监控需求的垂直切片

对一个 `*-MON-*` 依次完成：

1. 从 `capabilities.json` 读取完整 metric/event keys。
2. 从 `metrics.json`/`events.json` 读取类型、单位、scope、来源字段和告警策略。
3. 在目标适配器实现真实协议解析；厂商原始 DTO 不越过适配器边界。
4. 缺字段写 `ObservationError`；不支持更新 `support_state`；禁止写 0/normal 空值。
5. 按数据模型写组件、指标或事件，并保持批次 partial 语义。
6. API 返回规范类型、单位、质量、observed_at 和 freshness；不混合支持状态。
7. 页面使用统一业务组件，并显示未知、不支持、过期和错误的不同状态。
8. 添加领域、适配器 fixture、数据库、API、前端和故障测试。
9. 按 `HARDWARE_CERTIFICATION.md` 更新逐能力认证矩阵；正式支持前补真机对照并通过严格门禁。

完成前自问：设备不返回这个字段、返回未知枚举、单位变化、部分分页失败、时间错误时，系统是否仍诚实？

## 6. 人工功能的垂直切片

对一个 `*-ACT-*`：

1. 读取 `capabilities.json` 中该需求的全部动作。
2. 对每个 `(requirement_id, capability_key)` 找到唯一 `operations.json` profile；缺失即停止。
3. 根据 `channel` 分流：
   - `task`：snapshot plan/preview → confirm/idempotency → PostgreSQL task+audit → Worker row-lock/lease claim → live read-only preflight → dispatch fence → adapter execute → verify → terminal state；
   - `launch`：权限/能力/限流 → 一次性票据 → 握手/启动 → 会话审计，不创建副作用任务。
4. API 和前端使用 profile 的同一参数 schema；未知字段拒绝。
5. 高风险任务要求密码复验、设备名确认、60 秒预览令牌和幂等键。
6. 适配器只使用认证过的协议/命令模板；不得接受自由 CLI。
7. fence 前崩溃可重新领取；`side_effect=true` 在 fence 后只能查 job/回读，不能再次 execute；纯读取可按新 attempt 重试。
8. 只有 profile 的 success 条件满足才能 succeeded；命中 ambiguous 条件必须 verification_required。
9. 自动化覆盖成功、明确失败、超时、设备拒绝、断连、Worker 崩溃、重复提交和越权。
10. 所有动作在 release 前补逐能力真机证据；有副作用动作必须记录维护窗口、fence、设备响应/job 和回读。

## 7. 示例：`CORE-ACT-02`

正确实现路径：

```text
CORE-ACT-02
  -> capabilities.json: interface.admin.set
  -> operations.json: CORE-ACT-02:interface.admin.set
  -> parameter: discovered interface_id + boolean enabled
  -> API: operation preview/submit
  -> adapter: versioned Huawei VRP template
  -> DB: task/lease/fence/events/audit
  -> verification: read back interface.admin_status
  -> UI: high-risk preview + reauth + exact device-name confirmation
  -> tests: T-CORE-ACT-02 + target-model hardware evidence
```

错误实现包括：在 Vue 里拼 `shutdown`、提供自由命令文本框、只看到 SSH 返回 0 就成功、断线后自动重发、给设备列表加批量关闭端口。

## 8. 跨契约变更矩阵

| 变更 | 必须同步 |
| --- | --- |
| 原始需求变化 | source snapshot、project spec、capabilities、相关细化契约、trace、tests、ADR |
| 指标/事件键变化 | capabilities、metrics/events、adapter、DB/API、UI、tests、trace、ADR |
| 动作参数/风险/验证变化 | capabilities、operations、API/OpenAPI、UI、adapter、tests、trace、ADR |
| 状态/错误变化 | glossary、data、API、UI、adapter、tests、migration、ADR |
| API 变化 | API doc、OpenAPI、generated TS、frontend、contract tests、trace、ADR |
| 数据库变化 | data doc、Alembic、upgrade/rollback checks、tests、ADR |
| 部署变化 | architecture、security、deployment、compose/offline bundle、tests、ADR |
| 真机目标/支持范围变化 | hardware targets、certification schema/matrix、adapter、fixtures、tests、risk、ADR |

只改一层不算完成。校验器通过也不代表真机语义通过。

## 9. PR/交付证据包

每个工作项最终必须列出：

```text
requirement_or_platform_id:
capability_metric_event_keys:
operation_profile_ids:
changed_contracts:
openapi_operation_ids:
database_migrations:
frontend_routes_components:
adapter_and_protocol_path:
failure_and_ambiguity_behavior:
permissions_reauth_confirmation:
audit_events:
automated_test_ids_and_results:
hardware_evidence_or_experimental_reason:
hardware_matrix_record_ids:
docs_and_trace_updates:
remaining_risks_or_none:
```

“代码已写”“测试大致通过”“稍后补文档”不是证据。

## 10. AI agent 交接要求

交接信息必须让下一位参与者无需读取聊天记录：

- 已完成和未完成按需求编号列出；
- 指明实际修改文件和迁移；
- 给出执行过的精确验证命令与结果；
- 说明真机/fixture 的型号、固件和来源；
- 列出所有 `verification_required`、experimental、proposed ADR 或阻断；
- 不声称未执行的测试通过，不把模拟器写成真机。

## 11. 最终停止条件

以下任一项成立，功能不得标记完成：

- 来源编号或 profile 缺失；
- 真实适配路径、失败语义或验证方法不明确；
- API、页面和机器契约不同；
- 权限、复验、确认、幂等、fence、审计任一被绕过；
- 自动化证据缺失；
- 需要真机认证但没有证据；
- 文档、追踪、OpenAPI、迁移或测试未同步；
- `scripts/check-design.ps1` 失败。
