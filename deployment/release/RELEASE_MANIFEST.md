# Warden 0.1.0-rc.1 交付清单（deployment/release/RELEASE_MANIFEST.md）

支撑：`PLT-08`（私有部署与发布交付；TRACEABILITY §6）。本文档把 `docs/DEPLOYMENT.md` §10（无公网交付包）
的每一项映射到**本仓库实际产物**并标注状态。版本状态：`0.1.0-rc.1`（`docs/RELEASE_CHECKLIST.md`：软件测试
全绿、真机认证 306/306 `not_started`、**0.1.0 未发布**；本清单不改变该判定）。

## 状态图例

- `done`：产物在本仓库/本机离线完成，可在无公网交付中使用；
- `BLOCKED-here`：需要 Docker/registry/联网漏洞库，本开发机**没有 Docker**（`deployment/README.md` 声明），
  已给出部署环境可执行的精确命令与预期产物；执行结果不得在本机伪造，须由发布主机回填。

## DEPLOYMENT §10 逐项状态

| # | 交付项 | 状态 | 产物/命令（仓库根目录） | 部署环境（有 Docker）执行 |
| --- | --- | --- | --- | --- |
| 1 | 所有 OCI 镜像及 digest | `BLOCKED-here` | — | 应用镜像（api/worker/event-ingest/migrate 共用，`backend/Dockerfile`，构建须把 python/uv 基础镜像固定为 digest）：`docker build -f backend/Dockerfile -t warden-app:0.1.0 backend`；nginx 镜像（官方 nginx 稳定版 + `frontend` 构建产物，发布流水线构建，本骨架不交付该 Dockerfile——`deployment/README.md`）：`npm ci --omit=dev && npm run build` 后打入镜像得 `warden-nginx:0.1.0`；postgres 取官方 `postgres:18` 当前小版本。三个镜像各取 `sha256:<64hex>` 写入 `deployment/release/image-digests.env.example`（唯一剩余步骤=填文件，见下） |
| 2 | 镜像签名/校验和、SBOM、许可证清单和漏洞报告 | `BLOCKED-here`（部分前置 done） | Python/前端许可证清单与漏洞扫描输入：`deployment/release/python-licenses.txt`、`frontend-licenses.txt`、`python-vulnerabilities.txt`（生成与重新生成命令见 `deployment/release/README.md`） | 镜像 SBOM 与扫描：`syft scan warden-app@sha256:<hex> -o spdx-json > sbom-warden-app.spdx.json`（nginx 同）；`trivy image warden-app@sha256:<hex> --severity HIGH,CRITICAL`（含基础镜像 OS 层）；漏洞库必须联网；联网 `pip-audit`（输入清单见 `python-vulnerabilities.txt`）与 `npm audit`；签名：`cosign sign --key <key> warden-app@sha256:<hex>`（校验和清单随离线包） |
| 3 | Compose、Nginx、配置模板和安装脚本 | `done`（静态校验；未在 Docker 实机执行） | `deployment/compose/compose.yaml`、`deployment/nginx/`、`deployment/env/.env.example`、`deployment/scripts/`（`warden` CLI + 4 个入口脚本）、`deployment/postgres-init/`；CLI 用法与契约 `deployment/scripts/README.md` | 实机执行前先跑 `warden preflight`；交付包需含本清单 + 首次安装/升级演练记录（`deployment/drills/INSTALL_DRILL.md`、`UPGRADE_DRILL.md`） |
| 4 | Alembic 迁移、OpenAPI、设计文档和发布说明 | `done` | 迁移 `backend/migrations/`（头 `0015_system_state`，真实 PG18 迁移/回滚测试）；OpenAPI `backend/openapi.gen.json` + `frontend/src/api/generated`（漂移门禁）；设计基线 `docs/`（DEPLOYMENT/SECURITY/TEST_STRATEGY/ARCHITECTURE/DATA_MODEL/DEVICE_ADAPTERS/API_CONTRACT/UI_SPEC…）；发布说明 `docs/RELEASE_NOTES.md`、`docs/RELEASE_CHECKLIST.md`、`docs/KNOWN_LIMITATIONS.md` | 随交付包打包；无公网主机离线阅读 |
| 5 | 设备兼容性/真机认证矩阵 | `done`（结构）/ `blocked-with-evidence`（真机） | `contracts/hardware-targets.json`、`contracts/hardware-certification.schema.json`、`tests/hardware-certification/matrix.json`（10 目标 306 条记录，全部 `not_started`）；校验 `pwsh -File scripts/check-hardware-certification.ps1 -MatrixPath tests/hardware-certification/matrix.json`；严格门禁见 `docs/RELEASE_CHECKLIST.md` §3 | 真机认证在发布主机之外的维护窗口执行，按 `docs/HARDWARE_CERTIFICATION.md` 记录；未通过前不得把 rc.1 记为正式发布 |
| 6 | 安装、升级、回滚边界和故障处理手册 | `done`（程序文档）/ `BLOCKED-here`（演练执行） | 安装/升级/回滚边界：`deployment/drills/INSTALL_DRILL.md`、`UPGRADE_DRILL.md`、`ROLLBACK_BOUNDARIES.md`；合成负载冒烟 `deployment/release/LOAD_SMOKE.md` + `load-smoke-20260907.json`（**不是**现场验收，ADR-027） | 每份演练文档都注明：需 Docker 环境、尚未在本开发机执行；发布主机在无公网环境完成一次全新安装 + 一次升级演练后才能发布（DEPLOYMENT §10 最后一段） |
| 7 | 冒烟测试和验收脚本 | `done`（冒烟/自检）/ `BLOCKED-here`（容器内冒烟） | 冒烟驱动器 `backend/tests/performance/load_smoke.py`（合成、5 模拟设备 + 3 读者、默认周期、有界窗口，报告与语义见 `LOAD_SMOKE.md`）；仓库 2136 后端 + 177 前端测试全绿（M6T3b） | 演练冒烟 = `INSTALL_DRILL.md`/`UPGRADE_DRILL.md` 内嵌命令（/health/ready、引导登录改密、入网 1 台测试设备、`GET /system/status` 全组件 ok、容器内 `python -m app.workers.run --once` 路径由 entrypoint 执行）；现场验收负载运行另行按 `TEST_STRATEGY.md` §5 |
| 8 | 追踪/发布核对记录 | `done` | `scripts/check-traceability.ps1` 51/51 全绿、`tests/traceability/closeout.json`；`scripts/check-design.ps1` 基线通过；`docs/DECISION_LOG.md`、`docs/TRACEABILITY.md`、`docs/RISK_REGISTER.md` | 与交付包一起归档 |

## 镜像 digest 固定（唯一剩余步骤 = 填文件）

Compose 通过 `${WARDEN_IMAGE_APP:-warden-app:0.1.0}` / `${WARDEN_IMAGE_NGINX:-warden-nginx:0.1.0}` /
`${WARDEN_IMAGE_POSTGRES:-postgres:18}` 三个变量引用镜像（`deployment/compose/compose.yaml`；Compose 变量插值
读取项目 `.env`，即 `deployment/compose/.env`，非秘密值模板在 `deployment/env/.env.example` 第 75–79 行已有
digest 固定说明）。发布主机产出 digest 后：

1. 把 `deployment/release/image-digests.env.example` 的三行按真实 digest 填好；
2. 将三行合并进 `deployment/compose/.env`（或直接以该文件覆盖对应变量）；
3. 校验：`docker compose -f deployment/compose/compose.yaml config | grep -E 'image:'` 应显示
   `@sha256:<64hex>` 形式，且 `warden preflight` 第 7 项（`@sha256:` 64 位 hex 校验、占位符 REPLACE 判失败）通过。

**填好该文件并把其值带入 `deployment/compose/.env` 是镜像 digest 固定的唯一剩余步骤**；本机无 Docker，
不执行、不伪造 2/3 步结果（`deployment/release/README.md` 阻断项 1–4 与本条目同步）。

## 阻断项的预期回填位置（发布主机）

- `image-digests.env.example` → 填值后的副本进入交付包与部署 `.env`；
- `sbom-warden-app.spdx.json` / `sbom-warden-nginx.spdx.json` + trivy 报告 → 放入 `deployment/release/`；
- 联网 `pip-audit` 结果（输入 = `python-vulnerabilities.txt` 的 `name==version` 清单）与 `npm audit` 报告 → 放入 `deployment/release/`；
- 离线镜像包（`docker save` + 校验和清单）与一次全新安装 + 升级演练记录 → 随交付包归档，演练按 `deployment/drills/` 执行。

## 相关文档

- 无公网交付定义：`docs/DEPLOYMENT.md` §10；部署骨架声明：`deployment/README.md`；
- 离线安全产物与阻断项：`deployment/release/README.md`；发布判定：`docs/RELEASE_CHECKLIST.md`；
- 验收负载与门槛：`docs/TEST_STRATEGY.md` §5（门槛只在现场验收运行生效，ADR-027）。
