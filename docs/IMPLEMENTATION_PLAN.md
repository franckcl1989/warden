# Warden 0.1.0 实施蓝图

状态：`APPROVED_BASELINE`

## 1. 实施原则

- 采用单仓库模块化单体，先建立稳定领域契约，再并行设备适配；
- 所有参与者按 `DEVELOPMENT_PLAYBOOK.md` 执行，不依赖聊天上下文补全设计；
- 每个工作项必须引用需求编号或明确的平台支撑编号；
- 先实现失败、权限、审计和幂等骨架，再接真实危险操作；
- 设备适配器可以并行，但统一能力键、DTO、错误和契约测试由核心维护者控制；
- 前端不等待所有适配器完成，使用 OpenAPI 和模拟器按设备类型垂直开发；
- 没有真机证据的能力不进入正式支持矩阵。

## 2. 工程初始化

### 2.1 根目录

应包含：

- `Makefile` 或跨平台任务入口，统一 lint/test/build/compose 命令；
- `.editorconfig`、`.gitattributes`、`.gitignore`；
- `frontend/`、`backend/`、`deployment/`、`docs/`、`tests/`；
- 依赖锁文件、镜像 digest、SBOM 生成配置；
- CI 工作流；
- `AGENTS.md`。

### 2.2 前端基线

- Vue 3 + TypeScript strict + Vite；
- feature-first 目录；
- Vue Router 路由权限；
- Pinia 仅存认证和跨页面必要状态，服务端数据使用查询缓存封装；
- OpenAPI 生成类型；
- Element Plus 主题和 ECharts；
- Vitest、Vue Test Utils、Playwright；
- ESLint、Prettier、vue-tsc。

### 2.3 后端基线

- Python 3.13，`pyproject.toml` 和锁文件；
- FastAPI application factory；
- Pydantic settings，Secret 文件读取；
- SQLAlchemy 2 + Alembic；
- PostgreSQL 持久化任务领取、租约和单个 Worker 服务；
- Ruff、mypy strict、pytest；
- 领域/应用/适配器/基础设施依赖门禁；
- OpenAPI 稳定 operationId。

## 3. 里程碑

### M0：仓库与质量基线

产出：

- 工程目录、锁文件、Compose 开发环境；
- CI 格式/类型/单元/迁移/OpenAPI/secret scan；
- PostgreSQL/Nginx 开发启动；
- 文档链接和追踪校验脚本；
- 机器契约加载、代码生成/校验入口，以及 metrics/events/operations/alerts 注册表；
- 真机目标/认证 schema 与 `check-hardware-certification.ps1` 的 CI 入口；
- 统一错误、日志、request ID 和健康检查。

完成门禁：空业务骨架可在全新机器启动；迁移、前后端测试和离线构建路径通过。

M0 结束前不得手写第二套指标、事件、动作或告警枚举。生成器输出必须可删除后从 `contracts/` 完整重建，CI 验证生成物无漂移。

### M1：认证、设备接入与安全基础

产出：

- 用户、角色、会话、CSRF、Argon2id；
- 设备/凭据/能力数据模型；
- AES-GCM 主密钥和轮换骨架；
- SSRF CIDR 和 TLS 指纹固定；
- 登录、用户设置、设备列表、添加/编辑/停用；
- `probe`/`discover` 统一适配器契约和假适配器；
- 审计只追加和数据库权限约束。

完成门禁：无真实设备也能用假适配器完成安全接入；越权、凭据泄露、SSRF 和迁移测试通过。

### M2：采集、指标、事件、告警和任务引擎

产出：

- 单个 Worker 服务中的调度循环、独立采集/操作并发池和恢复扫描器；
- collection/metric/component/event/alert/task/file 表；
- 指标分区、聚合和保留；
- 健康/可达性/新鲜度/告警语义；
- 两阶段操作预览、确认、幂等、设备互斥和验证状态机；
- 文件流式上传、哈希、加密和受控下载；
- SSE；
- 总览、任务、告警、文件和审计基础页面。

完成门禁：假设备执行成功、明确失败、超时、Worker 崩溃和结果不明的端到端流程；API/Worker/主机重启恢复通过。

### M3：服务器监控与管理

按以下顺序：通用 Redfish → Dell overlay → Lenovo → Huawei → xFusion → Inspur。

产出：

- `SRV-MON-01..08` 全部监控；
- 服务器专用详情页；
- `SRV-ACT-01..07` 操作；
- KVM 启动描述符；
- TSR/SEL/系统日志产物；
- VirtualMedia 和 UpdateService/OEM；
- 五种管理卡 fixture、模拟集成和真机认证报告。

完成门禁：五种管理卡在逐能力认证矩阵中每个记录均为 `hardware_passed`，或有精确证据和用户接受引用的 `unsupported_with_evidence`；不得把单台实际服务器结果外推到整个管理族。

### M4：群晖 NAS 监控与管理

产出：

- DSM 登录/session 和版本化 API 客户端；
- `NAS-MON-01..06`；
- NAS 专用详情页；
- `NAS-ACT-01..06`；
- SMART 异步任务、备份/快照状态、支持包和 SNMP Trap 配置；
- DS224+、DS225+ 真机认证。

完成门禁：两个型号的监控与操作证据完整；DSM 版本差异和套件依赖有明确能力状态。

### M5：华为交换机监控与管理

产出：

- SNMPv3/v2c 客户端、MIB 映射、计数器速率；
- Syslog/Trap 接收器；
- VRP SSH 命令执行器、分页/提示符/错误解析；
- 浏览器 SSH/Telnet 终端；
- `CORE-MON-01..06`、`CORE-ACT-01..07`；
- `ACCESS-MON-01..05`、`ACCESS-ACT-01..06`；
- 核心/接入交换机专用详情页；
- 三个目标型号真机认证。

完成门禁：端口、光模块、PoE、配置和升级路径在目标型号/VRP 版本通过；CLI 注入和结果不明测试通过。

### M6：系统整合与发布硬化

产出：

- 全页面状态/权限/空态/错误态统一；
- 根据现场设备清单生成验收负载并完成容量测试和优化；
- 安全测试、SBOM、镜像签名、许可证清单；
- 离线交付包；
- 无公网安装、兼容升级和回滚边界演练；
- 51 条需求追踪证据收口；
- 发布说明和已知限制。

完成门禁：`PROJECT_SPEC.md` 第 7 节和 `TEST_STRATEGY.md` 发布候选门禁全部通过。

## 4. 可并行工作流

M2 完成稳定适配器/任务契约后可并行：

- Team/Agent A：服务器通用 Redfish 与厂商 overlays；
- Team/Agent B：DSM 适配和 NAS 页面；
- Team/Agent C：Huawei SNMP/SSH 和交换机页面；
- Team/Agent D：前端通用组件、任务/文件/审计；
- Team/Agent E：模拟器、契约、安全、性能和部署。

并行边界：

- 不得各自发明能力键、错误码、任务状态或 DTO；
- `domain/`、OpenAPI 公共 schema 和迁移公共表由单一负责人合并；
- 厂商差异只提交到对应 adapter 子目录和认证 fixture；
- 任何跨边界需求先新增 ADR，不以临时代码耦合解决。

## 5. 工作项模板

每个 issue/任务必须包含：

```text
标题：
需求编号/平台支撑编号：
用户可见结果：
能力键与适配器：
机器契约 profile/定义：
API operationId：
页面/组件：
数据模型/迁移影响：
权限与风险级别：
失败、超时、重试和核验语义：
审计内容：
自动化测试 ID：
真机认证要求：
文档/追踪矩阵更新：
完成证据：
```

缺少需求编号或平台支撑理由的任务不得进入开发。

## 6. 编码约束

- Python/TypeScript 均启用严格类型；`Any`/`unknown` 必须在协议边界收窄；
- 所有厂商响应先解析为适配器内部 DTO，再映射领域对象；
- 禁止在路由处理器、Vue 组件或 Worker 调度代码中拼厂商命令；
- 禁止使用通用 `execute_command(device, text)` 业务接口；
- 时间、单位和枚举在适配层归一化；
- 操作日志采用结构化字段，不拼接凭据和原始请求；
- 大文件、诊断输出和时间序列使用流式/分页；
- 数据库查询明确索引和上限，禁止无界列表；
- 所有后台任务幂等地写状态，但有副作用设备调用本身不得自动重放。
- task 直接由 PostgreSQL 行锁/租约领取并使用 dispatch fence；有副作用 profile 在 fence 后只能核验，纯读取只按契约创建新 attempt。

## 7. 合并门禁

每个 PR：

- 关联工作项和需求编号；
- 设计契约没有未记录变化；
- lint、类型、单元、迁移、API 契约、前端测试通过；
- 新能力包含适配器契约 fixture 和错误测试；
- 权限、审计、脱敏和幂等测试存在；
- OpenAPI、文档、追踪矩阵同步；
- 无高危依赖漏洞或 Secret；
- Reviewer 明确检查范围是否漂移。

设备危险操作 PR 在合并前可以使用模拟器，但进入 release 分支前必须关联真机认证证据。

## 8. Definition of Done

功能完成意味着：

- 用户在设计规定页面能看到/执行；
- 前端只调用正式 OpenAPI；
- 后端只调用统一适配器；
- 数据和任务状态符合模型；
- 权限、确认、审计、错误和恢复完整；
- 自动化测试与真机证据满足测试策略；
- 文档、ADR、追踪和发布说明一致；
- 不包含临时成功、未解释待办、占位按钮或绕过安全的调试入口。

## 9. 版本控制与发布

- 主分支始终可构建；
- 发布版本使用 `0.1.0-rc.N` 候选，满足全部门禁后标记 `0.1.0`；
- 数据库 schema、OpenAPI 和适配器认证矩阵随版本归档；
- 发现真实设备兼容问题时优先修正适配器和认证矩阵，不改变统一语义；
- 任何范围删减必须由用户明确批准并更新 `PROJECT_SPEC.md`，不能通过“已知限制”偷偷移出 0.1.0。
