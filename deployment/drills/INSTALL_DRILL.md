# 首次安装演练（deployment/drills/INSTALL_DRILL.md）

> **本演练需 Docker 环境，尚未在本开发机执行（无 docker）。** 本文件是可执行清单；执行记录、输出与偏差
> 必须在发布主机回填后归档到交付包（DEPLOYMENT §10：无公网环境完成一次全新安装后才能发布）。
> 所有命令在部署主机（Linux + Docker Engine/Compose v2）上以宿主机管理员身份执行；`warden` CLI 安装方式见
> `deployment/scripts/README.md`。

对应 `docs/DEPLOYMENT.md` §6 首次安装 11 步；前置材料：发布交付包（含
`deployment/release/RELEASE_MANIFEST.md` 所列镜像/清单/digest/模板）。

## 0. 环境声明（执行前填写）

- 主机名 / IP / 管理网段 / 日期时间（NTP 状态）：
- 交付包与镜像 digest 来源（`image-digests.env.example` 填值文件）：
- 现场验收负载清单及其散列（如可用，`TEST_STRATEGY.md` §5；无清单不得做容量承诺）：

## 1. 预检：时间、磁盘、Docker 与管理网路由（DEPLOYMENT §6-1）

```bash
date; timedatectl status                      # 时间合理、NTP 尽量开启（preflight 第 2 项）
df -h /srv                                    # 可用 SSD ≥ 100 GiB 仅用于启动与功能验证（DEPLOYMENT §1）
docker version; docker compose version        # Docker Engine + Compose v2
ip route get <设备管理网示例IP>                # 管理网路由可达
```

## 2. 导入带 digest 的离线镜像包并验证（DEPLOYMENT §6-2 / §10）

```bash
# 离线包由发布主机 docker save 产出（本机未执行；命令模板见 RELEASE_MANIFEST.md）
docker load -i warden-images-0.1.0-rc.1.tar
docker images --digests                       # 核对三个镜像 digest 与 image-digests.env.example 一致
# 校验和/签名清单随包核对（sha256sum -c / cosign verify）
```

## 3. 创建目录、账号、TLS 与 Secret（DEPLOYMENT §6-3 / deployment/README.md 目录表）

```bash
mkdir -p /srv/warden/{postgres,files,tls,secrets}
chown 999:999 /srv/warden/postgres            # PostgreSQL 数据（0700）
chown 101:101 /srv/warden/tls                 # Nginx 证书（fullchain.pem、privkey.pem，0700/0750 公钥）
chmod 0700 /srv/warden/{files,secrets}
# 证书放入 /srv/warden/tls/；以下 7 个 Secret 文件写入 /srv/warden/secrets/（全部 0600 非空）：
#   credential_master_key  file_master_key  session_secret  csrf_secret
#   postgres_dsn  postgres_dsn_migrate  postgres_superuser_password
# 文件清单与密码字符集约束见 deployment/README.md「持久化目录」表
```

## 4. 非秘密配置 + preflight（DEPLOYMENT §6-4）

```bash
cp deployment/env/.env.example deployment/compose/.env
# 填写：WARDEN_PUBLIC_URL / 采集与保留 / 文件配额 / 事件接收 / WARDEN_ALLOWED_DEVICE_CIDRS（必填，空=探测全拒）
# WARDEN_BOOTSTRAP_ADMIN_USERNAME；镜像引用改为 digest（image-digests.env.example 填值后合并）
warden preflight                              # 第 7 项：占位符 REPLACE 或非法 digest 判失败
```

## 5. 启动 PostgreSQL 并等待健康（DEPLOYMENT §6-5）

```bash
docker compose -f deployment/compose/compose.yaml up -d postgres
docker compose -f deployment/compose/compose.yaml ps postgres   # healthy
```

## 6. 一次性迁移（DEPLOYMENT §6-6，独立 warden_migrate 账号）

```bash
docker compose -f deployment/compose/compose.yaml run --rm migrate
# 验证：迁移日志结束于 upgrade head（0015_system_state）；重复执行安全（幂等）
```

## 7. 启动 API/Worker/Ingest/Nginx（DEPLOYMENT §6-7）

```bash
docker compose -f deployment/compose/compose.yaml up -d
docker compose -f deployment/compose/compose.yaml ps            # 全部 running/healthy（api 与 nginx 健康检查）
```

## 8. 创建首个管理员（DEPLOYMENT §6-8，users 表非空时拒绝）

```bash
warden bootstrap-admin <用户名>               # 密码从 stdin 读取，不出现在命令历史
# 验证：再次执行同一命令必须被拒绝（users 表非空）
```

## 9. 登录并立即修改密码（DEPLOYMENT §6-9）

1. 浏览器打开 `https://<public-url>`（或 API 登录）用引导账号登录；
2. 系统强制先改密（其余路由被门禁拦截）——设置正式密码；
3. 清空 `deployment/compose/.env` 的 `WARDEN_BOOTSTRAP_ADMIN_USERNAME` 后 `warden preflight` 复核。

## 10. 验证系统状态与一台测试设备连接（DEPLOYMENT §6-10）

```bash
curl -fsS https://127.0.0.1/health/live ; curl -fsS https://127.0.0.1/health/ready
# 浏览器 /system 系统状态页：api/database/file_storage/worker/ingest 组件 ok、无排队积压
# 入网 1 台测试设备：设备管理网内真实设备 → 探测/保存 → readiness=ready、reachability=online
#   （无真机时按现场约定；模拟器只用于本机冒烟 backend/tests/performance/load_smoke.py，不算真机证据）
```

## 11. 保存安装报告（DEPLOYMENT §6-11）

- 记录：步骤 1–10 输出、digest 清单、Secret 文件指纹（不记录值）、迁移头、首次登录改密完成时间、测试设备连接证据；
- 无公网交付门禁：全新安装 + 升级演练都通过前不得发布（DEPLOYMENT §10）；升级演练见 `UPGRADE_DRILL.md`。

## 验证命令汇总（冒烟）

```bash
docker compose -f deployment/compose/compose.yaml ps
curl -fsS https://127.0.0.1/health/ready
curl -fsS https://127.0.0.1/api/v1/system/status -H 'Cookie: <会话>'   # 或 /system 页面
docker compose -f deployment/compose/compose.yaml logs --tail=100 worker   # 无 handler_failed/异常
```

回填区（发布主机执行后填写）：步骤完成时间 / 失败与偏差 / 产物归档位置。
