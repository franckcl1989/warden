# 升级演练（deployment/drills/UPGRADE_DRILL.md）

> **本演练需 Docker 环境，尚未在本开发机执行（无 docker）。** 对应 `docs/DEPLOYMENT.md` §8 升级与回滚；
> 执行记录与输出必须在发布主机回填后归档（无公网交付须完成一次兼容升级演练，DEPLOYMENT §10）。
> 维护模式只由宿主机 `warden maintenance on|off` 提供，无 Web API/UI 切换入口（ADR-026）。

适用：0.1.0-rc.1 内后续 0.1.x 补丁升级（例如 0.1.1）。**跨 0.1.x 的不可逆/不兼容迁移不属于本文档范围**：
命中时必须停止升级并另行形成版本决策（DEPLOYMENT §8 末段、`ROLLBACK_BOUNDARIES.md`）。

## 0. 升级前状态核对

```bash
warden preflight                              # 主机/配置/digest 预检（含占位符判失败）
docker compose -f deployment/compose/compose.yaml ps           # 当前栈健康
# 记录当前版本：镜像 tag/digest、Alembic 迁移头（当前 0015_system_state）
# 核对目标交付包：镜像 digest（image-digests.env.example 填值文件）、迁移范围（新增迁移必须 additive-only）
# 执行前完成数据库/文件卷基础设施备份或按现场约定确认无备份依赖（ADR-023：0.1.0 不提供备份服务，
#  基础设施备份由部署方负责——升级窗口前按部署方策略执行，不在 Warden 能力内）
```

## 1. 开启维护模式（DEPLOYMENT §8-1）

```bash
warden maintenance on
# 验证：
#   - CLI 输出成功并写审计（audit_logs action=maintenance.on，requirement_id=PLT-08）；
#   - 浏览器 /system 系统状态页显示维护模式（或 GET /api/v1/system/status maintenance_active=true）；
#   - 新人工操作/launch 被拒绝（503 maintenance_mode），监控读取与管理查询仍可用
```

## 2. 等待运行中危险任务完成（DEPLOYMENT §8-2）

```bash
# 系统状态页/API：operations_running=0、verification_required=0、无 queued/running 副作用任务；
# 固件/配置类任务绝不强制中断；等待其 succeeded/failed/verification_required 终态
```

## 3. 导入新镜像与发布清单（DEPLOYMENT §8-3）

```bash
docker load -i warden-images-0.1.x.tar
docker images --digests                       # 与目标 image-digests.env.example 核对
# 把三行 WARDEN_IMAGE_* 新 digest 合并进 deployment/compose/.env
warden preflight                              # 镜像引用校验通过
```

## 4. 兼容性检查与 migrate（DEPLOYMENT §8-4）

```bash
# 兼容性检查：核对目标发布说明（docs/RELEASE_NOTES.md）的迁移清单与本文档回滚边界：
#   新增迁移必须 additive-only（无不可逆变更）；存在不可逆迁移 → 停止升级，另行版本决策
docker compose -f deployment/compose/compose.yaml run --rm migrate   # 一次性迁移（独立 warden_migrate 账号）
# 验证：日志结束于新 head；升级前后校验 SQL 按发布说明执行（如适用）
```

## 5. 依次重建后台服务、API、Nginx（DEPLOYMENT §8-5）

```bash
docker compose -f deployment/compose/compose.yaml up -d --no-deps worker event-ingest   # 后台先行
docker compose -f deployment/compose/compose.yaml up -d --no-deps api
docker compose -f deployment/compose/compose.yaml up -d --no-deps nginx
docker compose -f deployment/compose/compose.yaml ps              # 全部 healthy；worker/api/nginx 已用新镜像
```

## 6. 冒烟、采集与只读真机检查（DEPLOYMENT §8-6 / TEST_STRATEGY §5 参考）

```bash
curl -fsS https://127.0.0.1/health/ready
# 浏览器：/system 状态页全部组件 ok；总览/设备/告警可读
# 采集检查：观察 1–2 个采集周期（默认 30–60 s）内设备 last_collected_at 更新、无新增 failed/partial 异常
# 只读真机检查：至少 1 台现场设备最新指标/状态可读（只读；不做有副作用操作）
# 日志检查：docker compose logs --tail=200 worker api | grep -E '"level":"error"|handler_failed' 应无输出
# 合成负载冒烟（可选、非验收）：按 deployment/release/LOAD_SMOKE.md 在备用环境运行
#   （现场验收负载运行另行按 TEST_STRATEGY.md §5 执行）
```

## 7. 解除维护模式（DEPLOYMENT §8-7）

```bash
warden maintenance off
# 验证：
#   - CLI 成功并写审计（action=maintenance.off）；
#   - /system 状态页维护模式消失；
#   - 一条新低风险操作可正常 preview/confirm（或按现场约定只读验证后放行人工操作）
```

## 回滚边界声明（本节必须在升级前读）

- 0.1.x 迁移默认只允许向后兼容的 additive 变更；数据库迁移**不自动 downgrade**；
- 新版本含不可逆或不兼容迁移时，本升级必须停止并另行形成版本决策，不能在 0.1.0 基线虚构通用回滚能力
  （DEPLOYMENT §8）；逐项边界与验证命令见 `ROLLBACK_BOUNDARIES.md`；
- 维护模式下已 dispatch 的任务继续执行/核验（DEPLOYMENT §8）：升级期间不得重启到一半时强制中断危险任务。

回填区（发布主机执行后填写）：新旧版本与 digest / 迁移前后 head / 各步骤时间与输出 / 失败与偏差 /
维护模式审计行定位 / 产物归档位置。
