# Warden 负载冒烟（deployment/release/load-smoke-*.json）

支撑：`PLT-08`（私有部署与发布交付）——M6T4 交付；验收负载与发布门禁见 `docs/PROJECT_SPEC.md` §5/§7。
对应发布清单条目：`deployment/release/RELEASE_MANIFEST.md` 第 6 项。

## 重要声明：合成冒烟，不是现场验收运行

**本目录的负载数字来自一个有边界的合成冒烟：5 个测试模拟器设备 + 3 个模拟并发读者的真实
API/Worker/PostgreSQL 栈，不是现场验收负载运行，不构成任何容量承诺（ADR-027）。**

- 现场验收必须按 `docs/TEST_STRATEGY.md` §5 生成并保留验收负载清单（实际/计划设备数、每类设备数、
  端口与组件数、活跃数值序列、采集/保留周期、并发用户与文件大小，含清单散列），再按该清单运行。
- `P95 < 500 ms / P99 < 1 s`（普通读取）、调度 `P95 < 10 s`、操作提交 `2 s`、状态变化 `2 分钟` 等门槛
  只在**现场验收运行**上生效；本冒烟只报告数字，不做 pass/fail 判定。
- 模拟器（`backend/tests/simulators/`）是测试设备模拟器，任何时候都不是真机证据（ADR-018）。
- 现场无公网交付/发布门禁要求见 `docs/DEPLOYMENT.md` §10 与本目录 `RELEASE_MANIFEST.md`。

## 冒烟是什么

`backend/tests/performance/load_smoke.py`（可经 venv 直接运行，无 pytest）：

1. 在专用 PostgreSQL 18 实例上重建 `warden_smoke` 库并执行全部 Alembic 迁移（真实迁移路径）；
2. 启动真实的 API 进程（uvicorn，单进程如部署形态）与真实 Worker 进程（`python -m app.workers.run`）；
3. 通过真实 HTTP API 以**部署引导流程**创建管理员（bootstrap CLI → 首次登录强制改密）、3 个只读用户；
4. 通过真实探测（SSRF 策略与协议端口白名单全部生效，无任何 monkeypatch）入网 5 个模拟设备：

   | key | 模拟器 | 适配器 | 说明 |
   | --- | --- | --- | --- |
   | srv_dell | Redfish healthy/dell | `server.dell_idrac` | HTTP 8000 |
   | srv_inspur | Redfish healthy/inspur | `server.inspur_ibmc` | HTTP 8080 |
   | dsm | DSM healthy/DS224+ | `nas.synology_dsm` | HTTP 80 |
   | sw_core | SNMPv3 代理 core_s5732（48GE+4XGE） | `switch.huawei_vrp_core` | UDP 8443 |
   | sw_access | SNMPv3 代理 access_s5735（48GE+4SFP） | `switch.huawei_vrp_access` | UDP 443 |

   模拟器绑定到本机管理网 IP（回环被平台 SSRF 策略拒绝，与管理网真实设备同路径）；
5. 预热到每台设备至少 2 次 `metrics` 采集成功后，进入有界窗口（默认 600 s）：
   Worker 按默认周期（reachability/health 30 s、metrics 60 s、logs 120 s、discovery 6 h）持续采集，
   3 个并发读者每 ~4 s 读取 overview / devices / device / metrics latest / alerts，每两拍一次
   metrics series；
6. 度量（定义与单位全部写入 JSON 报告）：

   | 度量 | 定义 |
   | --- | --- |
   | API 读取 P50/P95/P99/最大（ms） | 每个读者、每个端点标签的请求耗时分位数 |
   | 采集 claim 延迟 P95（ms） | `started_at - scheduled_at`（调度到期到 Worker 领取开始的排队时间，含领取轮询粒度），按类型与总体 |
   | 调度网格延迟 P95（ms） | 同一 (device, type) 相邻两次 `scheduled_at` 间隔减去配置周期（正值为调度器 10 s tick 的量化延迟） |
   | 队列深度 | 窗口内每 15 s 采样：`scheduled+running` 采集行数、最老未领取年龄；窗口结束时各状态计数 |
   | DB 增长 | `pg_database_size` 窗口前后差 + 各表行数增量 |
7. 输出 JSON 报告到 `deployment/release/load-smoke-YYYYMMDD.json`，随后清理模拟器/进程并删除冒烟库。

## 运行方式

```powershell
# 需要：仓库 venv；一台有并发余量的 PostgreSQL 18（见下）；管理网 IP 上的 5 个空闲模拟端口
# （http 8000/8080/80、UDP 8443/443，须处于 SSRF 端口白名单内）
& backend\.venv\Scripts\python.exe backend\tests\performance\load_smoke.py `
    --window-seconds 600 --readers 3 --sim-host <本机管理网 IPv4> `
    --pg-dsn "postgresql://<user>@127.0.0.1:<port>/postgres" `
    --report deployment\release\load-smoke-20260907.json
```

数据库要求：本仓库开发机的共享测试 PG（`127.0.0.1:55433`，`WardenTestPG`）以
`max_connections=8 / shared_buffers=16MB / autovacuum=off` 运行，真实 API+Worker 并发会立刻打满连接池，
因此本冒烟使用同机 PostgreSQL 18 二进制、独立数据目录的实例（`max_connections=60`、`shared_buffers=128MB`、
`autovacuum=on`；已记录在报告 `run.postgres`）。其他环境请自行准备有并发余量的 PG 18；测试专用的小连接数
实例不能用于本冒烟。

## 已记录运行（2026-09-07，window=600 s，readers=3）

文件：`deployment/release/load-smoke-20260907.json`。关键数字：

- API 读取：3 用户 × 764 请求 = **2292 次，全部 HTTP 200**；单用户总体 P95 ≈ 30–52 ms、P99 ≈ 47–77 ms
  （P99 主要来自 `metrics/latest` 大页读取与 `overview` 的告警/注意力聚合）；
- 采集：窗口内完成 275 次运行（另有预热与收尾运行），claim 延迟总体 P95 ≈ **967 ms**、P99 ≈ 1067 ms；
  调度网格延迟 P95 ≈ 10.3 s（等于一个 10 s 调度 tick 的量化延迟，见上表定义）；
- 队列：窗口内最大同时活跃采集 2 个、最老未领取年龄峰值 8.4 s；窗口结束无排队/运行中/失败行
  （`succeeded=363, partial=2`——2 个 partial 为交换机首次速率采集缺缓存样本的真实 partial，非错误）；
- DB：窗口内数据库增长 **4.7 MB**（`metric_points` +9,121 行、`collection_runs` +275、
  `metric_rollups_5m` +454、`ui_events` +387，其余表无增量；逐表数字见报告）；
- 告警：2 条活跃（access 交换机按 profile 自带的 PoE 端口问题由告警引擎真实开出）。

## 已记录运行（M6T4b 修复后重跑，2026-09-07，window=600 s，readers=3）

文件：`deployment/release/load-smoke-20260907-m6t4b.json`。同一场景在 M6T4b 修复
（migration 0016：COALESCE 表达式唯一索引 → 部分唯一索引对，ON CONFLICT arbiter 不再含参数）
后重跑，验证下节可靠性现象的修复：

- **Worker 零失败**：`worker_log.handler_failed_count = 0`（修复前 9 次）；
  API 读取 3×~760 = 2282 次全部 HTTP 200；claim 延迟总体 P95 ≈ 954 ms、P99 ≈ 1087 ms；
  调度网格延迟 P95 ≈ 10.2 s（不变，仍是一个 10 s tick 的量化延迟）；
- 队列：窗口结束 `succeeded=349, partial=2`（与修复前相同的诚实 partial 语义），无排队/运行中/失败残留；
- DB：窗口内增长 4.6 MB（`metric_points` +8,676、`metric_rollups_5m` +662、`collection_runs` +272、
  `ui_events` +388；`metric_latest` 稳定 926 行、delta 0）；活动告警 2。
- 回归测试：`tests/infrastructure/test_upsert_prepare.py` 在 psycopg3 自动 PREPARE 默认配置与
  `prepare_threshold=None` 两种设置下均 0 失败（单连接 60 次最新值 upsert + 30 次 rollup 重生成）。

## 观察到的平台可靠性现象（必须随本报告一起读）

运行期间 Worker 出现 9 次 `handler_failed`（`collection_pool` 内 `metric_latest` upsert 报
`InvalidColumnReference: there is no unique or exclusion constraint matching the ON CONFLICT specification`），
每次都被“release for recovery，never re-executed”路径释放，后续由维护循环/下一次调度自愈
（窗口结束状态无失败行）；9 次失败约占窗口内运行的 3%。该现象已用最小复现确认并定位：

- 触发面：`observation_store` 对 `metric_latest` 的
  `ON CONFLICT (device_id, coalesce(component_id, $1::uuid), metric_key)` 推断目标与
  `uq_metric_latest_device_component_key`（`COALESCE(component_id, '00000000-…'::uuid)` 表达式唯一索引）
  的匹配依赖参数能否在规划期被常量折叠；
- 当 psycopg3 连接启用自动服务端 PREPARE（默认 prepare_threshold=5）时，同一连接上同文本 upsert 执行若干次后
  切换为 generic plan，推断稳定失败（单测：默认配置 40 次尝试失败 ~30–50 次，`prepare_threshold=None` 时
  0/120 失败）；
- 平台引擎（SQLAlchemy+psycopg3）未显式关闭该行为，因此真实 Worker 在复用连接上会间歇性失败；
  现有测试套件因单进程串行、低重复执行次数而从未暴露。

**这不是容量结论，而是发布前必须形成决策的可靠性发现**（建议方向：连接参数禁用 psycopg3 自动 PREPARE、
或把冲突目标改为文本字面量、或迁移为 `NULLS NOT DISTINCT` 普通唯一索引——均属平台代码/迁移变更，需 ADR，
超出 M6T4 的“deployment/ 增量”范围，已上报 M6T4 报告待决策）。

**修复（M6T4b，已实施）**：采用“部分唯一索引对”方向 —— migration `0016_metric_dedupe_partial`
把 metric_points/metric_latest/metric_rollups_5m/1h 的 COALESCE 表达式唯一索引改写为
`(…, component_id, …) WHERE component_id IS NOT NULL` 与 `(…, metric_key, …) WHERE component_id IS NULL`
两两一组，upsert 的 `ON CONFLICT` arbiter 只含常量谓词、不再含参数，正确性不再依赖 planner/prepare
行为；修复后重跑本节见上（零 handler_failed，回归测试覆盖两种 prepare 设置）。ADR 记录见控制者决策链。

## 文件

| 文件 | 内容 |
| --- | --- |
| `load-smoke-20260907.json` | 2026-09-07 记录运行完整报告（含场景、逐端点延迟、claim/调度、队列、DB 增长、worker_log 错误计数） |
| `load-smoke-20260907-m6t4b.json` | 2026-09-07 M6T4b 修复后同场景重跑报告（`handler_failed_count=0`） |
| `backend/tests/performance/load_smoke.py` | 冒烟驱动器（含本 README 所载语义的实现） |

现场复用：按 `TEST_STRATEGY.md` §5 生成验收负载清单并保留散列后，可在部署环境以真机/真实规模改写设备表
（`load_smoke.py` 的 `SIM_DEVICES` 常量与探测载荷）运行；**未按现场清单执行的任何运行都不得当作验收**。
