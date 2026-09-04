# Warden 0.1.0 发布安全产物（deployment/release/）

支撑：`docs/SECURITY.md` §10（依赖锁文件、SBOM、漏洞扫描和许可证检查作为发布门禁）、§13 安全验收、`docs/TEST_STRATEGY.md` §4/§8（发布候选：安全扫描 + SBOM/许可证/镜像签名）。
里程碑：M6 — 系统整合与发布硬化（`docs/IMPLEMENTATION_PLAN.md` M6；本目录产物由 M6T2 生成，docker/registry 相关阻断项在 M6T4 交付声明中记录）。

## 重要声明：哪些可以做、哪些被阻断

本仓库开发环境**没有安装 Docker、没有 registry 访问、没有网络工具安装许可**（uv 不在 PATH、venv 无 pip/pip-audit、无 gitleaks、不允许新增全局工具）。因此：

- ✅ **可以离线、诚实生成**：依赖许可证清单（Python + 前端）、Python 漏洞扫描的**输入清单**与阻断说明。
- ❌ **被 docker/registry 阻断、必须由 M6T4 在具备 Docker/registry/网络的发布主机上完成**：
  1. 镜像 SBOM（对构建出的 `warden-app` / `warden-nginx` 镜像运行 syft/trivy 类工具）；
  2. 镜像 digest 固定与签名（`compose.yaml` 当前引用 tag，无公网交付必须替换为 `@sha256:` digest 引用并完成签名，`deployment/env/.env.example` 与 `docs/DEPLOYMENT.md` §10 已有占位说明）；
  3. 离线镜像包（无公网全新安装/升级演练，`docs/DEPLOYMENT.md` §10；`deployment/README.md` 已声明本骨架未经 Docker 实机执行）；
  4. 联网漏洞库扫描（见 `python-vulnerabilities.txt` 内精确命令）与 `npm audit`。
- 这些阻断项及其交付语句统一记录在 M6T4 的交付说明中（见 `.superpowers/sdd/IMPLEMENTATION_PLAN/progress.md` M6T4 条目），本目录不伪造任何扫描结论。

## 产物清单

| 文件 | 内容 | 生成命令（仓库根目录） | 何时重新生成 |
| --- | --- | --- | --- |
| `python-licenses.txt` | backend venv 全部已安装发行版的 name/version/许可证；`runtime`/`dev-only` 按 `backend/uv.lock` 运行时闭包标记；0 个 UNKNOWN（有则必须人工复核） | `backend\.venv\Scripts\python.exe scripts\generate_python_licenses.py` | 依赖变更（uv.lock 更新）或发布前 |
| `python-vulnerabilities.txt` | 诚实占位：工具状态、阻断说明、联网扫描精确命令、已安装发行版 `name==version` 清单（联网 pip-audit 的输入）。**不包含“无漏洞”声明** | `backend\.venv\Scripts\python.exe scripts\generate_python_vulnerabilities.py` | 发布前（联网执行后把扫描结果文件放入本目录） |
| `frontend-licenses.txt` | `frontend/node_modules` 全量（含 dev 工具链）的 name/version/许可证/物理份数；`npm ls --json` 与磁盘一致性核对；UNKNOWN 数在文件头声明 | `backend\.venv\Scripts\python.exe scripts\frontend_licenses.py` | 前端依赖变更（package-lock.json 更新）或发布前 |
| `README.md` | 本文件 | — | 本目录内容变化时 |

## 范围与诚实性规则

- 许可证取值只读包元数据（Python：`License-Expression` → `License` → OSI classifier → `UNKNOWN`；前端：`license` → `licenses[]` → `UNKNOWN`）。长文本许可证截断标注 `<text>`，全文在包元数据内。清单不自行推断、不跨包外推。
- 运行镜像只装运行时子集：后端 `backend/Dockerfile` 使用 `uv sync --no-dev --frozen`，nginx 镜像由发布流水线 `npm ci --omit=dev` 构建。本目录清单**覆盖全部安装（含 dev 工具链）**，属有意的过覆盖；发布流水线应在此基础上收敛到镜像实际包含的包并复核。
- 漏洞状态必须来自联网漏洞库比对（PyPI JSON/OSV），离线机器无法给出真值。`python-vulnerabilities.txt` 是**输入清单 + 阻断说明**，不是扫描结果；把该文件当“无漏洞证明”使用属于误用。
- 镜像级漏洞（操作系统层、python:3.13-slim / nginx 基础镜像）必须由容器镜像扫描（syft/trivy + digest 固定）覆盖，见上表阻断项 1–3。

## 发布门禁中的位置（TEST_STRATEGY §8）

- 每个提交：secret scan（CI `.github/workflows/ci.yml`，gitleaks）。
- 每个合并请求：依赖/镜像/许可证相关检查可开始进入 MR 门禁。
- 发布候选：SBOM/许可证策略复核 + 联网漏洞扫描 + 离线安装/升级演练 + 镜像签名，全部依赖 M6T4 的 docker/registry 步骤；本目录离线产物为该门禁的前置输入。

## 相关文档

- 依赖与许可证策略：`docs/SECURITY.md` §10；安全验收：`docs/SECURITY.md` §13；测试门禁：`docs/TEST_STRATEGY.md` §4/§8。
- 部署与无公网交付：`docs/DEPLOYMENT.md` §10、`deployment/README.md`。
- 生成脚本：`scripts/generate_python_licenses.py`、`scripts/generate_python_vulnerabilities.py`、`scripts/frontend_licenses.py`。
