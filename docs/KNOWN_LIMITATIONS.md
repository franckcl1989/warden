# Warden 0.1.0-rc.1 已知限制

- 状态：随 `0.1.0-rc.1` 候选发布（M6T3 生成；M6T5 最终门禁复核：无新增限制——M6T4 负载冒烟暴露的指标 upsert 可靠性缺陷已由 M6T4b 修复（ADR-033，迁移 `0016_metric_dedupe_partial`，冒烟重跑 0 `handler_failed`），是修复不是残余限制，技术记录见 RELEASE_NOTES M6 摘要与迁移 docstring）
- 日期：2026-09-07
- 规则：本文件只记录已实现功能/发布项的边界与诚实依据，每项映射到 ADR、里程碑报告或台账（`.superpowers/sdd/IMPLEMENTATION_PLAN/progress.md`）；**不得**把未实现项当作"限制"移出 0.1.0 范围——范围删减必须由用户明确批准并更新 PROJECT_SPEC（IMPLEMENTATION_PLAN §9）。M6T3 追踪收口发现的唯一缺口（PLT-08 `GET /system/status`）已在 M6T3b 交付（commit `cf375a9`），本文件不再单列"发布前未决缺口"节。

## 1. 硬件认证：全部阻塞（不是限制，是门禁未过）

- 开发环境没有任何目标真机：10 个目标（Dell/Inspur/xFusion/Lenovo/Huawei 服务器管理卡、DS224+/DS225+、S5732-H48XUM2CC、S5731S-S48P4X-A、S5735-L48P4S-A1）306 条认证记录全部 `not_started`（`tests/hardware-certification/matrix.json`）。
- `pwsh -File scripts/check-hardware-certification.ps1 -MatrixPath tests/hardware-certification/matrix.json -RequireReleaseReady` 无法通过；矩阵诚实记录，未伪造证据（M3T6/M4T5/M5T6 门禁记录）。
- 正式支持声明只能来自逐能力真机矩阵（hardware-targets.json `formal_support_rule`：只有 `hardware_passed` 可宣称支持）；模拟器、按钮存在或同系列其他型号资料不能代替真机证据（ADR-018/019，PROJECT_SPEC §7）。
- 收口方式：在部署现场对目标型号/固件执行认证并回填矩阵。

## 2. 协议与厂商路径的 [sim] 依据

- 华为全部 OID 子树/VRP CLI 模板为 `[sim]` DSL 夹具，待官方文档或真机证据（ADR-018，M5T2/M5T3 记录）；真机输出钉扎、PTY/回显假设、MORE 分页、恢复指纹不匹配的重连语义都需要在认证时复核（M5T3）。
- 华为交换机光模块/端口族 >5000 行截断走查标志被丢弃（M5T2，认证时复核规模语义）。
- DSM 操作族与监控 API 依据行标注 `[guide]`（Synology 官方错误码指南，ADR-031）/`[sim]`（M4T1/M4T2/M4T3），待 DS224+/DS225+ 真机认证。
- 服务器五厂商 OEM 专属路径（TSR、KVM、冷复位、固件 OEM 成员名）为 experimental/有证据前不支持（M3T5 裁决：文档站不可达时不得臆造行为）。

## 3. 依赖部署环境或联网工具链的发布项未在本地执行

- Docker/registry 依赖项：compose 运行时、镜像 SBOM/签名/摘要（digest）、离线交付包、安装/升级演练——文件与流程存在（M0T7 部署骨架、M6T4 制品任务），执行需要部署环境；Dockerfile `uv:latest` 未固定摘要、nginx http2 需 >=1.25.1 等项在发布演练时确认（M0T7 台账）。宿主 CLI（`deployment/scripts/warden`，含 PLT-08 `maintenance on|off`）在本无 Docker 主机上仅静态验证（`bash -n`）+ 等义 SQL 在真机 PG 实测（M6T3b 记录）。
- Python 依赖漏洞扫描（pip-audit）未执行：pip/pip-audit 不在 venv（uv 管理）、uv 不在 PATH、任务禁止新装工具、advisory DB 为联网资源——没有运行扫描、没有"无漏洞"声明；`deployment/release/python-vulnerabilities.txt` 诚实记录工具状态、发布期命令与 64 项 `name==version` 清单，结果归属 M6T4（M6T2 记录）。
- npm audit 同属联网项，与 registry 项一并计入 M6T4 交付声明（`deployment/release/README.md`）；gitleaks 本地未安装——CI gitleaks（每次推送运行）为权威密钥扫描门禁且对本分支每次推送通过，本地以离线正则扫描作为等效（M6T2 记录）。

## 4. 容量与性能：无现场验收负载

- 不存在站点验收负载（ADR-027）：24 小时负载运行需要现场设备清单；不得把 100 台、30,000 序列、500 GiB 等数字写成产品承诺。
- 已文档化的是默认值与真实 schema 上的分层保留/分区行为；正式部署的 CPU/RAM/磁盘建议是现场产物（ARCHITECTURE §8）。

## 5. 运行平台边界

- 速率推导：样本缓存为进程内，平台重启丢失一个采集间隔（首个点无速率，诚实报错而非伪造）；站点要求单 worker 进程运行（多进程交替会导致持续首样本错误）（M5T2）。
- 审计与操作任务事件流豁免自动保留清理（只追加双保护，ADR-030），物理清理带外执行；相关表在 0.1.0 会长于 365 天保留窗口。
- 审计 403 拒绝详情有限（权限审计记录条目化，不含攻击者可控长文本）。
- 浏览器终端在 0.1.0 无 PTY（交互 SSH 为 `[sim]` 语义，resize 为空操作；M5T4）。
- 管理卡/DSM 复位类操作：设备离线窗口大于一次性核验上限（约 120 秒）时任务进入 `verification_required`，需要管理员核验恢复，不自动重放（M3T3/M4T3，fence 语义 DEVICE_ADAPTERS §9）。
- SNMP v2c 与 Telnet 为弱协议：显式选择 + 持久界面警告 + 审计，无静默降级路径（M5T1/M5T4）。
- DSM 双因素（2FA）账号不支持自动化：需要专用非 2FA 账号（M4 记录）。
- 事件接收计数（PLT-08 收口后，M6T3b）：接收消息总数与 ingest 存活心跳持久化到 `ingest_heartbeat` 单行表，由 `/system/status` 呈现 ingest `ok/stopped`（空闲不等于降级，`degraded` 无诚实推导不产生）；细粒度丢弃分类（未注册 v2c 社区、v3 USM 拒绝、不可解析、归属不明、队列满等）仍只是 ingest 进程内计数器 + 刷新周期日志，0.1.0 不落库、不对外（M5T1/M6T3b——/system/status 不虚构该面）。
- `/system/status` worker/ingest 推导语义（PLT-08，M6T3b）：0.1.0 无持久 worker 心跳（0015 之后未加表），worker 状态由采集/任务行活动推导——完全空闲站点与停机 worker 无法靠 DB 活动区分，空闲按约定显示 `ok` 并附说明字段，由运维结合延迟/活动字段判读；ingest 心跳行缺失（未部署/从未启动）按 `stopped` 呈现（M6T3b 契约文档化推导）。
- trap 的 sysUpTime 不换算为墙钟时间，`occurred_at` 缺失时以接收时间为准并诚实标注（M5T1）。

## 6. 其余台账边界摘录

| 项目 | 限制 | 依据 |
| --- | --- | --- |
| 指标回滚 | 迟到点只按 15 分钟回溯折入；跨分区边界当日保留在保留窗口内 | M2T3 |
| 会话表增长 | 随审计量增长（审计外键受只追加触发器约束） | ADR-030 类 |
| 设备编辑并发 | 乐观锁（应用层），并发 PATCH 存在丢失更新窗口 | M1T3 |
| 重新连接测试 | 瞬时失败可能被标记为"配置错误"（M1T3 记录；滞回/词表核对按 M2 记录处理） | M1T3 |
| 限流/限制器 | 登录限流在反向代理后按对端计数（nginx 单 peer 部署注意事项）；launch 预览限制器为进程内 | M1T1/M3T4 |
| 终端孤儿会话 | 拨号成功后审计异常极边缘场景行关闭不重放 | M5T4 |
| IPv6 管理地址 | `console.web.open` 已按 RFC 3986 对 IPv6 字面量加括号（M6T1 `_bracket_ipv6_host`）；带 scope-id（zone）的 IPv6 字面量 `ipaddress` 无法解析、原样透传——无专门处理或拒绝，真机 v6 管理地址场景需复核 | M5T5→M6T1 |
| 文件删除冲突 | 返回 `device_busy` + 关联任务（无文件专用 409 码） | M2T5 |
| 上传并发限制 | 建议性（先查后插），不构成硬上限 | M2T5 |
| 引导管理员 | 并发双跑未处理 IntegrityError | M1T1 |
| 审计页过滤 | 资源类型过滤为常量（无契约枚举） | M2T7 |
| 未知事件键 | 无归属事件键在未配置时诚实 `not_configured`，不伪造告警源 | M5T2/M5T3 |
| 环境认证 | 开发 PG 单机/计划任务启动；重启后需 `schtasks /run /tn WardenTestPG` | 台账运行裁决 |
