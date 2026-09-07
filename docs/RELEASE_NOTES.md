# Warden 0.1.0-rc.1 发布说明

- 状态：`0.1.0-rc.1` 候选说明（M6T3 生成；M6T4 容量/部署制品与 M6T5 最终门禁尚未执行，正式发布声明以 M6T5 复核后的 `docs/RELEASE_CHECKLIST.md` 为准）
- 日期：2026-09-07
- 支持编号：PLT-08（发布）；本版本覆盖 51 条原始需求（飞书《边端硬件监控及功能实现项》）

## 1. 里程碑交付摘要

| 里程碑 | 内容 |
| --- | --- |
| M0 仓库与质量基线 | 需求/契约基线与快照（51 需求、52 指标、5 事件、39 操作画像、50 端点、27 错误码、10 硬件目标、306 认证记录）；后端骨架、契约加载/校验、代码生成漂移测试；数据库层与 Alembic 迁移（真机 PG18 验证）；前端脚手架（Vue3+Vite+TS 严格）；认证矩阵生成；部署骨架（compose/nginx/CLI，未在本地运行）。 |
| M1 认证、设备接入与安全基础 | 本地认证与三类角色、会话、CSRF、锁定与审计；AES-GCM 凭据库与密钥轮换骨架、SSRF 守卫、TLS 指纹钉扎；设备模型与设备 API（连接测试/能力发现）；审计只追加权限与查询；前端登录、用户与设备页。安全对抗门禁 12/12 通过。 |
| M2 采集、指标、事件、告警、任务引擎与基础页面 | PostgreSQL 持久化任务队列（行锁领取/租约/恢复/分派 fence）；采集管线与当前问题引擎（只承认设备明确状态、离线和过期，日志事件不自动升级为告警）；指标回滚/分区/保留；操作预览/确认/幂等/互斥/核验；受控文件平台；SSE 实时流；前端概览/告警/操作/文件/审计与设备详情页签。 |
| M3 服务器监控与管理 | Redfish 客户端与模拟器；通用 Redfish 采集与操作（电源、管理卡复位、支持包、虚拟介质、固件、资产）；launch 一次性票据与 KVM 前端流程；五厂商 overlay（Dell iDRAC/Inspur iBMC/xFusion iBMC/Lenovo XCC/Huawei iBMC）——OEM 专属路径为 experimental/有证据前不声称支持。 |
| M4 群晖 NAS | DSM 客户端与模拟器、版本化 API 发现与官方错误码映射（ADR-031）；采集（磁盘/存储池/温度风扇电源/卷使用率/UPS/系统日志与连通性）；操作（电源、DSM 控制台、支持包、S.M.A.R.T、备份状态、固件与 SNMP 配置）；NAS 前端类型页签与 DSM 控制台 launch。 |
| M5 华为交换机 | SNMPv3/v2c 客户端与 MIB 映射、Syslog/Trap 接收（事件入站）、弱协议显式 opt-in；核心/接入交换机采集与速率推导（重启丢失一个间隔语义诚实）；VRP SSH 执行器与 CLI 操作、SFTP；浏览器终端（WS 一次性票据，no-PTY）；核心/接入前端页签、端口/PoE/光模块视图。 |
| M6 系统整合与发布硬化 | UI 状态一致性收口与前端遗留项；安全收尾（与时钟无关的限流测试、密钥/依赖扫描、离线 license 与漏洞制品）；确定性套件门禁（连续两轮全绿）；PLT-08 收口：`GET /system/status`、维护模式状态面与 503 门禁、摄取存活心跳、`/system` 页面（M6T3b，commit `cf375a9`）；追踪收口：51 需求机器核对（`scripts/check-traceability.ps1` + `tests/traceability/closeout.json`，51/51 全绿无未决缺口）、发布说明、已知限制与发布清单。 |

套件规模（M6T2b 门禁实测）：后端 2111 通过 / 78 跳过 / 0 失败；前端 163 通过。M6T3b 全量实测（含 PLT-08 系统状态/维护模式/摄取心跳测试）：后端 2136 通过 / 78 跳过 / 0 失败；前端 25 文件 / 177 通过。

## 2. 平台与角色

- 认证：本地账号密码（Argon2id），每用户一个固定角色：管理员、运维员、观察员。
- 必要平台支撑 PLT-01..09（详见 TRACEABILITY §6，仅承载原始需求，不构成新业务模块）：
  - PLT-01 本地认证与三类角色；PLT-02 设备接入与凭据保护；
  - PLT-03 采集与状态语义；PLT-04 当前问题展示；
  - PLT-05 操作任务与恢复（PostgreSQL 条件领取，无消息中间件）；
  - PLT-06 受控文件；PLT-07 操作审计（只追加）；
  - PLT-08 私有部署与必要运行状态（只读 Web）；PLT-09 实时进度与终端。
- 范围边界按 PROJECT_SPEC §4 执行：不做机房/机柜/组织/租户/CMDB/工单/通知中心/编排/容量规划/数据库备份服务/可编辑通用告警规则；0.1.0 只有持久化卷，无备份产品能力。

## 3. 设备家族与适配器状态

正式支持声明只来自 `contracts/hardware-targets.json` 的逐能力真机矩阵（当前 306 条全部 `not_started`，见第 5 节）；下列状态为开发环境的实现与验证状态，不构成对任何真实型号、固件组合的支持承诺：

| 家族 | 适配器 | 状态 |
| --- | --- | --- |
| 通用服务器（Redfish） | `server.redfish`（common） | 模拟器验证（TEST-DEVICE 模拟器，M3 全流程）；真机认证待现场。 |
| 服务器厂商路径 | Dell iDRAC / Inspur iBMC / xFusion iBMC / Lenovo XCC / Huawei iBMC overlay | experimental：OEM 成员名、TSR、KVM、冷复位、固件 OEM 路径在厂商文档/真机证据前不实现不宣称（M3T5 裁决）。 |
| 群晖 NAS | `nas.synology_dsm` | 模拟器 + 官方指南依据（`[guide]`/`[sim]` 行，ADR-031）验证；DS224+/DS225+ 真机认证待现场。 |
| 华为核心/接入交换机 | `switch.huawei_vrp_core` / `switch.huawei_vrp_access` | 模拟器验证；全部 OID 子树与 VRP CLI 模板为 `[sim]` 依据（ADR-018）；S5732/S5731S/S5735 真机认证待现场。 |
| 开发假适配器 | `fake.simple` | 仅开发/API 使用，不出现在设备向导（ADR-032）。 |

`hardware-targets.json` 声明的 10 个目标：服务器 5（Dell/Inspur/xFusion/Lenovo/Huawei 管理卡族）、NAS 2（DS224+/DS225+）、核心交换机 2（S5732-H48XUM2CC、S5731S-S48P4X-A）、接入交换机 1（S5735-L48P4S-A1）。

## 4. 已知限制与升级/回滚边界

- 诚实清单见 `docs/KNOWN_LIMITATIONS.md`（每项映射到 ADR/台账证据），包括：硬件认证全部阻塞；华为 OID/CLI 与 DSM 操作族为 `[sim]` 依据；Docker 依赖与联网工具链的发布项（含 python/npm 依赖漏洞扫描）未在本地执行；无现场验收负载（ADR-027）；速率推导重启丢失一个间隔与单 worker 进程站点要求；审计/任务事件流豁免自动保留清理（ADR-030）；终端 no-PTY；管理卡复位离线窗口核验语义；弱协议显式 opt-in；DSM 2FA 账号不支持自动化；`/system/status` 的 worker/ingest 推导语义边界。
- 升级：0.1.x 仅允许前向附加数据库迁移；迁移与 OpenAPI、适配器矩阵随版本归档。
- 回滚：0.1.x 不提供降级；发布候选内问题优先修正适配器与矩阵，不改变统一语义（IMPLEMENTATION_PLAN §9）。

## 5. 认证状态

- 306/306 记录为 `not_started`（`tests/hardware-certification/matrix.json`）；`-RequireReleaseReady` 门禁无法通过。
- 原因：开发环境无任何目标真机（iDRAC/iBMC/XCC、DS224+/DS225+、S5732/S5731S/S5735）。
- 收口方式：按 ADR-018/ADR-019 在部署现场对目标型号/固件逐能力执行认证并回填矩阵；模拟器与按钮存在不能替代真机证据。

## 6. 完成定义声明

- 51 条原始需求逐条具备代码、API/页面路径与自动化测试引用（机器核对：`scripts/check-traceability.ps1`，逐条证据 `tests/traceability/closeout.json`）。
- 按 TEST_STRATEGY §9 与 PROJECT_SPEC §7：任一真机证据缺失、语义不一致或存在未决缺口时，0.1.0 均不可标记完成。本候选记录为 `0.1.0-rc.1`（待真机认证 + M6T4/M6T5 门禁），**不是 0.1.0**。
- M6T3 追踪收口曾暴露唯一实现缺口：`GET /system/status`（`system_status_get`，PLT-08，见 API_CONTRACT/ARCHITECTURE/DEPLOYMENT 与 `contracts/http-api.json` 白名单）及其前端占位页无实现、契约未定义响应结构、无任何台账延期记录。该缺口已由 M6T3b 补齐交付（commit `cf375a9`，控制者裁决授权）：组件状态诚实推导（api/database/file_storage/worker/ingest，`application/system_status.py`）、维护模式状态面（`system_state` 单行表 + `deployment/scripts/warden maintenance on|off` + 维护中 503 `maintenance_mode` 门禁）、摄取存活心跳（`ingest_heartbeat` 单行表）、`/system` 系统状态页与顶栏状态 chip（SSE `system.status_changed` 触发页面查询缓存失效）；迁移 `0015_system_state` 经真机 PG 迁移/回滚测试。机器核对现为 **51/51 全绿**：49/49 非 WS operationId 均在导出 OpenAPI（WS 豁免按设计），`tests/traceability/closeout.json` `ok: true`，无未决代码缺口；遗留边界全部诚实登记于 `docs/KNOWN_LIMITATIONS.md`。逐项状态见 `docs/RELEASE_CHECKLIST.md`。
