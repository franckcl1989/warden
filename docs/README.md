# Warden 0.1.0 设计蓝图

状态：`APPROVED_BASELINE`  
更新时间：2026-09-01  
适用版本：0.1.0

## 一句话定义

Warden 是一个前后端分离、私有化部署的 Web 系统，用于监控和管理一个小型私有化机房中的硬件设备。

## 范围总原则

飞书《边端硬件监控及功能实现项》是 0.1.0 所有人工硬件业务操作的唯一来源。平台可以补充认证、设备接入、采集、任务、文件、审计等必要支撑，但不得发明新的硬件业务动作或扩展成通用资产/机房管理系统。

## 文档优先级

发生冲突时按以下优先级处理：

1. 飞书原文；
2. `SOURCE_BASELINE.md` 中最近复核的原始快照；
3. `PROJECT_SPEC.md` 中的 51 个工程需求编号；
4. `DECISION_LOG.md` 中状态为 `accepted` 的最新决策；
5. `contracts/` 机器契约；
6. `TRACEABILITY.md` 中的端到端追踪；
7. 各专题设计文档；
8. 代码注释和任务描述。

如飞书原文发生变化，必须先更新 `PROJECT_SPEC.md`、追踪矩阵和决策记录，再修改实现。

## 设计文档地图

| 文档 | 作用 |
| --- | --- |
| `SOURCE_BASELINE.md` | 已复核的飞书原表本地快照与禁止误读说明 |
| `PROJECT_SPEC.md` | 原始需求、边界、质量目标和验收口径 |
| `PRODUCT_DESIGN.md` | 页面、用户流程、状态语义和交互约束 |
| `UI_SPEC.md` | 前端布局、组件、视觉语义和页面状态规范 |
| `ARCHITECTURE.md` | 技术选型、组件、数据流、部署与关键原则 |
| `DEVICE_ADAPTERS.md` | 设备协议、能力键、适配器接口和厂商差异 |
| `DATA_MODEL.md` | 数据实体、约束、状态机和保留策略 |
| `API_CONTRACT.md` | REST/SSE/WebSocket 契约与错误语义 |
| `SECURITY.md` | 认证、授权、凭据、危险操作和审计 |
| `DEPLOYMENT.md` | 私有化部署、持久化边界、升级和运行检查 |
| `TEST_STRATEGY.md` | 测试层级、模拟器、真机认证与发布门禁 |
| `HARDWARE_CERTIFICATION.md` | 逐目标、逐能力的真机证据格式和发布判定 |
| `IMPLEMENTATION_PLAN.md` | 工程结构、里程碑、任务拆分和完成定义 |
| `DEVELOPMENT_PLAYBOOK.md` | 人与 AI agent 的机械执行流程、停止条件和交接格式 |
| `TRACEABILITY.md` | 需求到能力、页面、API、适配器和测试的闭环 |
| `GLOSSARY.md` | 全项目统一术语、状态和禁用歧义表达 |
| `RISK_REGISTER.md` | 真实设备、部署、安全和交付风险及关闭条件 |
| `ADVERSARIAL_REVIEW.md` | 多轮反证、弱 agent 演练、已修问题和残余门禁 |
| `BLUEPRINT_AUDIT.md` | 本轮设计完整性自检结果与证据 |
| `DECISION_LOG.md` | 已接受设计决策及其理由 |

机器契约位于 `contracts/`：`capabilities.json` 管需求白名单，`metrics.json` 管指标，`events.json` 管事件，`operations.json` 管动作执行，`alert-rules.json` 管内置告警，`http-api.json` 管端点与 OpenAPI operationId，`error-codes.json` 管稳定错误和重试分类，`hardware-targets.json` 管 0.1.0 真机目标，`hardware-certification.schema.json` 管逐能力证据格式。后端注册、OpenAPI、前端类型/文案和测试数据应从这些文件生成或校验，不得维护另一套近似清单。

## 统一设计哲学

1. **能力来源唯一**：业务能力来自原始矩阵，不从页面想象需求。
2. **真实设备优先**：以设备实际返回和真机验证为准，不假设所有厂商行为一致。
3. **统一语义、保留差异**：平台使用统一能力键，厂商差异封装在适配器内；不为统一而伪造支持。
4. **观察与操作分离**：采集可以重试，变更操作不能在结果不明时自动重放。
5. **状态必须可解释**：在线、健康、数据新鲜度、任务结果分别表达，禁止用一个“正常/异常”掩盖原因。
6. **副作用可追踪**：每个操作都要知道谁、何时、对哪台设备、用什么参数、得到什么结果。
7. **小型部署优先**：单机 Docker Compose、单 PostgreSQL 持久化状态与任务；不引入 Redis、Celery、消息 outbox、集群或多租户复杂度。
8. **支撑也要有边界**：每个非飞书功能都必须证明自己是承载原始需求所必需；部署配置和内部实现不得包装成新的产品模块。
8. **端到端可验收**：每条原始需求都必须有能力键、适配路径、API、界面位置和测试证据。
