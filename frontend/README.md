# Warden 前端（M0T5 工程基线）

Vue 3.5 + TypeScript strict + Vite 8 的 feature-first 前端脚手架。页面当前为占位视图，业务逻辑按里程碑（M1/M2…）填充。

## 环境要求

- Node `>=20.19 || >=22.12`（CI 使用 Node 24 LTS；本地 v26 已验证）。首次开发需运行 `npm ci` 安装锁文件依赖，禁止改锁文件版本升级主版本（架构基线见 `docs/ARCHITECTURE.md` §2）。

## 常用命令（在 `frontend/` 下）

| 命令                              | 作用                                                                |
| --------------------------------- | ------------------------------------------------------------------- |
| `npm run dev`                     | 启动 Vite 开发服务器（默认 5173 端口）                              |
| `npm run lint`                    | ESLint（flat config，`--max-warnings 0`）                           |
| `npm run format` / `format:check` | Prettier 格式化/检查                                                |
| `npm run typecheck`               | vue-tsc 严格类型检查（app + node 两个项目）                         |
| `npm run test`                    | Vitest 单元/组件测试（happy-dom）                                   |
| `npm run build`                   | 类型检查 + 生产构建到 `dist/`                                       |
| `npm run test:e2e`                | Playwright e2e（M2 门禁启用；先 `npx playwright install chromium`） |

## 契约与代码生成流水线

前端类型只从提交的 OpenAPI 与机器契约生成，禁止手写第二套枚举：

- `src/api/generated/contracts.ts`：由后端 codegen 生成（`backend\.venv\Scripts\python.exe -m app.tools.codegen`，仓库根目录 `pwsh scripts/tasks.ps1 contracts`），产物入库，CI 校验无漂移。
- `src/api/generated/openapi.ts`：由 `npm run openapi-codegen` 生成 —— 先刷新 `backend/openapi.gen.json`（后端不可用时复用现有导出），再经 `openapi-typescript` 输出。产物入库，后续里程碑在 CI 校验漂移。
- 上述两个生成文件一律不手工编辑；修改契约后必须重新生成并提交。

## 目录约定

- `src/api/`：OpenAPI 生成类型与 fetch 封装（错误信封解析、CSRF 头槽位、request_id）。
- `src/components/`：业务组件层，见目录内 README（UI_SPEC §4）。
- `src/features/`：devices/alerts/operations/files/audit/users/system + login/overview，页面占位视图。
- `src/router/`：PRODUCT_DESIGN §2 的 11 条路由与认证守卫占位（M1 接入）。
- `src/stores/`：Pinia 仅存认证与跨页面必要状态（`auth.ts` 占位）。
- `src/styles/`：UI_SPEC §3 状态色与 Element Plus 主题令牌。
- `src/tests/`：Vitest 测试（client/router/App 外壳）。

## 部署

前端构建产物经 Nginx 同源托管（`deployment/nginx`），API 前缀 `/api/v1`；开发时可用 `VITE_API_BASE` 覆盖（见 `src/api/client.ts`）。
