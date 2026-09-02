# deployment/scripts：宿主机命令与容器入口

支撑需求：`PLT-08`（私有部署与必要运行状态；TRACEABILITY §6）。本目录的脚本只做部署级操作，不构成业务 API 或页面（ADR-026）。

## `warden` 宿主机 CLI

在部署主机（Linux + Docker Engine/Compose v2）上运行，不在容器内运行。安装方式：复制到 `PATH`（如 `/usr/local/bin/warden`），或通过 `WARDEN_DEPLOYMENT_DIR` 指向仓库 `deployment/` 目录。

```text
warden preflight                        # 部署前预检（DEPLOYMENT §6 步骤 1/4）
warden maintenance on|off               # 开启/关闭持久化维护模式并写审计（DEPLOYMENT §8）
warden bootstrap-admin <用户名>          # 创建首个管理员（仅 users 表为空时允许）
```

### preflight 检查项

1. docker 与 compose v2 可用，且 `docker compose config` 能解析；
2. 主机时间合理（早于 2025-01-01 判失败）、NTP 未激活给警告；
3. `/srv/warden/{postgres,files,tls,secrets}` 存在，postgres/files 可写，tls/secrets 权限建议；
4. 7 个 Secret 文件与 2 个 TLS 文件存在且非空（权限非 0600 给警告）；
5. `WARDEN_ALLOWED_DEVICE_CIDRS` 非空（为空判失败：设备探测全部拒绝，DEPLOYMENT §3/§5）；
6. `WARDEN_APP_ENV=production` 时 `WARDEN_PUBLIC_URL` 不得为 `http://`（DEPLOYMENT §5）；
7. 镜像引用若含 `@sha256:` 则校验 64 位 hex；仍为占位符（`REPLACE`）判失败。

### maintenance（DEPLOYMENT §8；ADR-026 仅宿主机入口）

- 通过 `docker compose exec -u postgres postgres psql`（容器内 postgres 系统用户、本机 socket peer 认证）执行 SQL，全程不接触任何密码；
- 前置检查：`system_state` 表必须存在（由 M2/M6 迁移创建），不存在时**明确报错拒绝继续**；
- 对 `system_state` 表键 `maintenance_mode` 做 upsert（值 `jsonb {enabled, source, set_at}`），并在 `audit_logs` 写一行审计（`audit_logs` 缺失时告警但不阻断状态变更）；
- 维护模式开启后 API 拒绝新任务和 launch，已 dispatch 任务继续执行/核验，监控读取与管理查询保持可用（行为由 API 侧实现，DEPLOYMENT §8）。

### bootstrap-admin（DEPLOYMENT §6 步骤 8）

- 前置检查（通过容器内 psql）：`users` 表不存在 → 提示先运行迁移；`users` 表非空 → **拒绝引导**；
- 通过后调用应用镜像内的 `python -m app.tools.bootstrap_admin`（`docker compose run`），密码从**标准输入**读取，绝不从 argv/命令历史读取（契约见下）；
- 引导仅此一条路径；引导完成后 Web 端创建后续用户，不提供可重复执行的引导命令。

## 前后向契约（本骨架与 M1/M2 的接口约定）

以下表结构与模块由后续里程碑实现，本仓库脚本已按以下契约调用；若后续实现调整，必须同步修改本目录脚本并走契约变更流程：

| 对象 | 契约 |
| --- | --- |
| `system_state` 表 | `key text PRIMARY KEY`、`value jsonb NOT NULL`、`updated_at timestamptz NOT NULL DEFAULT now()`；键 `maintenance_mode` 值 `{enabled: bool, source: text, set_at: text}`（M2/M6 迁移创建） |
| `audit_logs` 表（CLI 写入列） | `actor text`、`actor_session_id`（可空）、`action text`、`resource_type text`、`resource_id`、`result text`、`detail text`、`created_at timestamptz`（M2 迁移创建；CLI 只追加） |
| `users` 表 | DATA_MODEL §3.1 字段；引导只做“空表检查”，行写入由 `app.tools.bootstrap_admin` 负责 |
| `app.tools.bootstrap_admin` | M2 实现：users 表为空时创建首个管理员（Argon2id 参数见 SECURITY §2），密码从 stdin 或 `WARDEN_BOOTSTRAP_PASSWORD_FILE` 读取，拒绝时非零退出并写审计 |
| `postgres-init/01-accounts.sh` | 首次空数据目录时由官方镜像执行：从 DSN Secret 文件提取密码创建 `warden_app`（无超级用户/无建库）与 `warden_migrate`，授予 schema 访问；warden_app 另获 `CREATE ON SCHEMA public`（分区维护循环与 0008 所有权转移需要，PG18），`warden_migrate` 获 `warden_app` 成员资格（0008 把可清理表所有权转移给应用账号需要）。表级权限模型由迁移补充：0004 授予 SELECT/INSERT/UPDATE 并 REVOKE audit_logs 的 UPDATE/DELETE，0008 把可清理表（metric_points 及分区、rollups、events、alerts、operation_tasks、ui_events、sessions）所有权转移给 `warden_app`；audit_logs/operation_task_events 保持迁移账号属主 + 只追加触发器 |

## 容器入口脚本

| 脚本 | 用途 |
| --- | --- |
| `entrypoint-api.sh` | 校验 4 个应用密钥 + 应用 DSN 后 `exec uvicorn`（单进程，ARCHITECTURE §2/§3.2） |
| `entrypoint-worker.sh` | 校验密钥后 `exec python -m app.workers.run`（模块 M1 实现） |
| `entrypoint-ingest.sh` | 校验 DSN 后 `exec python -m app.workers.ingest`（模块 M1 实现） |
| `entrypoint-migrate.sh` | 校验迁移账号 DSN 后 `exec alembic upgrade head`（DATA_MODEL §12） |

入口脚本由 Compose 以只读方式挂载到容器 `/entrypoints/`；Secret 文件缺失时**拒绝启动**（DEPLOYMENT §5 启动检查），不得把缺失伪装成成功。

## 约束

- 秘密不进脚本、不进 Compose、不进 `.env`：只从 `/srv/warden/secrets/` 只读挂载读取；
- 维护模式没有 Web API/UI 切换入口（ADR-026）；不提供备份/PITR 命令（ADR-023）；
- 不写死容量承诺（ADR-027）：资源限制由现场验收负载决定，本目录无任何默认 CPU/内存上限。
