# Warden 0.1.0 部署（deployment/）

支撑需求：`PLT-08`（私有部署与运行状态）、`PLT-01..09`（全部平台支撑的运行容器形态，见 `docs/TRACEABILITY.md` 第 6 节）。

本目录是 0.1.0 的部署骨架，严格对应 `docs/DEPLOYMENT.md`、`docs/SECURITY.md` §11 与相关 ADR（ADR-002 单机 Compose、ADR-023 无备份/灾备、ADR-026 维护模式仅宿主机入口、ADR-027 无容量承诺）。

## 重要声明：本骨架未经 Docker 实机执行

**本仓库的开发环境没有安装 Docker**，`deployment/` 全部文件只完成了编写与静态校验（Shell `bash -n` 语法检查、YAML 解析校验、配置名交叉核对），**从未在装有 Docker 的主机上执行过 compose 栈**。首次安装/升级演练（DEPLOYMENT §10：无公网环境完成一次全新安装和升级）安排在 M6 进行，届时如与官方镜像行为不符（例如 Postgres 只读根文件系统与官方入口脚本的兼容性），以真机结果为准修正本目录文件。

## 目录结构

```text
deployment/
├─ compose/compose.yaml      # 服务编排（nginx/api/worker/event-ingest/postgres/migrate）
├─ nginx/
│  ├─ nginx.conf             # 主配置（含 conf.d）
│  └─ conf.d/warden.conf.template  # 443 服务器块模板（envsubst 注入证书路径）
├─ scripts/
│  ├─ entrypoint-api.sh      # API 入口（单进程）
│  ├─ entrypoint-worker.sh   # Worker 入口
│  ├─ entrypoint-ingest.sh   # 事件接收入口
│  ├─ entrypoint-migrate.sh  # 一次性迁移入口
│  ├─ warden                 # 宿主机部署命令（preflight/maintenance/bootstrap-admin）
│  └─ README.md              # CLI 用法与前后向契约
├─ env/.env.example          # 非秘密配置模板（复制为 deployment/compose/.env）
├─ postgres-init/01-accounts.sh  # 首次初始化：最小权限 warden_app / warden_migrate 账号
└─ README.md                 # 本文件
```

应用镜像构建文件在 `backend/Dockerfile`（api/worker/event-ingest/migrate 共用）；`warden-nginx` 镜像由发布流水线基于官方 nginx 稳定版内置前端构建产物（本骨架不交付该 Dockerfile）。

## 端口与网络（DEPLOYMENT §3）

| 端口 | 协议 | 用途 | 映射 |
| --- | --- | --- | --- |
| 443 | TCP | Web/API/SSE/WebSocket 唯一入口 | nginx |
| 80 | TCP | 可选，仅重定向到 443 | nginx（默认未发布，取消 compose 注释启用） |
| 162 | UDP | SNMP Trap | event-ingest 容器内 1162 |
| 514 | UDP/TCP | Syslog | event-ingest 容器内 1514 |

PostgreSQL 5432、API 8000 与文件卷**不发布到宿主机网络**；所有服务只在 Compose 内部网络通信。

## 持久化目录（DEPLOYMENT §4/§7）

```text
/srv/warden/
├─ postgres/   # PostgreSQL 数据（属主 999:999，0700）
├─ files/      # 受控文件：固件/ISO/配置备份/支持包（应用控制访问）
├─ tls/        # Nginx 证书，只读（fullchain.pem、privkey.pem；属主 101:101，0700）
└─ secrets/    # 密钥与 DSN 文件，只读（0600）
```

Secret 文件清单（全部 0600、非空）：

| 文件 | 内容 |
| --- | --- |
| `credential_master_key` | 设备凭据主密钥（AES-256-GCM，SECURITY §5） |
| `file_master_key` | 文件加密主密钥（配置备份/支持包，SECURITY §9） |
| `session_secret` | 会话签名 secret（SECURITY §2） |
| `csrf_secret` | CSRF secret（SECURITY §2） |
| `postgres_dsn` | 应用账号连接串：`postgresql://warden_app:<密码>@postgres:5432/warden` |
| `postgres_dsn_migrate` | 迁移账号连接串：`postgresql://warden_migrate:<密码>@postgres:5432/warden` |
| `postgres_superuser_password` | PostgreSQL 超级用户密码（初始化使用；应用不持有） |

密码只允许字符 `[A-Za-z0-9._-]`（避免 URL 编码与 SQL 引号转义问题）。数据库账号与密码唯一权威来自 `postgres_dsn*` 文件：首次初始化脚本从 DSN 提取密码创建账号（`postgres-init/01-accounts.sh`），请保证 `postgres_dsn` 与应用约定一致。应用/迁移账号为最小权限（无超级用户、无建库；SECURITY §11），表级授权由 M2 迁移补充。

0.1.0 不提供数据库备份服务、PITR、灾备编排或 RPO/RTO 承诺（ADR-023）：持久化边界就是上述宿主机目录与容器重建语义，基础设施备份由部署方现有主机/存储策略负责。

## 首次安装（DEPLOYMENT §6 清单）

1. 校验主机时间/NTP、磁盘与到设备管理网的路由；
2. 导入带 digest 的离线镜像包（DEPLOYMENT §10），把 `deployment/env/.env.example` 复制为 `deployment/compose/.env` 并填写（镜像引用改为 digest 固定形式）；
3. 创建目录、账号属主与 TLS 证书（见上表）：
   `mkdir -p /srv/warden/{postgres,files,tls,secrets}`，`chown 999:999 /srv/warden/postgres`，`chown 101:101 /srv/warden/tls`，TLS 证书放入 `/srv/warden/tls/`；
4. 写入 `/srv/warden/secrets/` 下 7 个文件（0600），运行 `warden preflight`；
5. `docker compose -f deployment/compose/compose.yaml up -d postgres`，等待健康；
6. `docker compose -f deployment/compose/compose.yaml run --rm migrate`（一次性 Alembic 迁移，独立迁移账号）；
7. `docker compose -f deployment/compose/compose.yaml up -d`（api/worker/event-ingest/nginx）；
8. `warden bootstrap-admin <用户名>` 创建首个管理员（密码从 stdin 读取；users 表非空时拒绝）；
9. 登录后立即修改密码；随后可清空 `.env` 中的 `WARDEN_BOOTSTRAP_ADMIN_USERNAME`；
10. 验证系统状态页与一台测试设备连接；
11. 保存安装报告。无公网交付必须完成一次全新安装与升级演练后才发布（DEPLOYMENT §10）。

> 骨架阶段提示：`worker` 与 `event-ingest` 的启动模块（`app.workers.run` / `app.workers.ingest`）由 M1 实现，在此之前这两个容器会明确报错退出并重启，属预期行为；API 与健康检查先可用。

## 日常运维（DEPLOYMENT §9）

- 每日检查：卷剩余空间、采集成功率、排队任务/租约/超时、Trap/Syslog 最近接收、TLS 证书与指纹变化；
- 升级窗口：`warden maintenance on` → 等待危险任务完成 → 导入新镜像 → `migrate` → 重建服务 → 冒烟 → `warden maintenance off`（维护模式无 Web API/UI 切换入口，ADR-026）；
- 备份边界：见 ADR-023，由部署方基础设施负责，不属于 Warden 能力。

## 更多文档

- 宿主机 CLI 用法与前后向契约：`deployment/scripts/README.md`
- 部署设计：`docs/DEPLOYMENT.md`；安全基线：`docs/SECURITY.md`；决策记录：`docs/DECISION_LOG.md`
