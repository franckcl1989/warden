# Warden 0.1.0-rc.1 发布核对清单

- 状态：`0.1.0-rc.1` 候选（M6T3 生成；M6T4/M6T5 执行后复核）
- 日期：2026-09-07
- 结论先行：**0.1.0 未发布**。状态记录为 `0.1.0-rc.1`（软件测试全绿；硬件认证阻塞；追踪收口 51/51 全绿，无未决代码缺口——M6T3 发现的 PLT-08 缺口已由 M6T3b 交付，commit `cf375a9`）。不得把本清单当作 0.1.0 发布记录（TEST_STRATEGY §9）。

## 1. PROJECT_SPEC §7 版本验收原则逐项

| # | 验收条件 | 状态 | 证据 |
| --- | --- | --- | --- |
| 1 | 51 条原始需求全部具备代码、API、界面和测试追踪 | done | `scripts/check-traceability.ps1`：51/51 需求至少一个后端测试文件引用、前端静态引用与适配器方法路径；`tests/traceability/closeout.json` |
| 2 | 每个目标厂商/型号完成能力发现并形成兼容性记录 | done（软件侧）/ blocked-with-evidence（真机侧） | 10 目标 306 条认证记录生成且结构有效；状态全部 `not_started`（无真机）；发现/能力行由模拟器驱动并有 `[sim]`/`[guide]` 依据 |
| 3 | 有副作用的能力在真机或用户认可的等价实验环境完成验收 | blocked-with-evidence | 无任何目标真机（iDRAC/iBMC/XCC、DS224+/DS225+、S5732/S5731S/S5735）；`-RequireReleaseReady` 门禁失败（见第 3 节输出）；模拟器验收不能替代（ADR-018/019） |
| 4 | 不支持的能力如实标记并给出设备/固件证据，不占位 | done | OEM 未接线键为 `unsupported` + `mapping_missing`；未配置键为 `not_configured` + 原因码；DSM `psu.status` 无 WebAPI 源如实 `unsupported`；各适配器测试断言 |
| 5 | 安全、离线安装、兼容升级和故障注入门禁通过 | done（软件门禁）/ blocked-with-evidence（部署项） | M1T6 对抗门禁 12/12；M2T6 故障注入；M6T2 密钥/依赖扫描与限流确定性；Docker 相关发布项未在本地执行（见 KNOWN_LIMITATIONS §3） |
| 6 | 文档与实际 OpenAPI、数据库迁移和部署清单一致 | done | 全部 49 个非 WS operationId 均在导出 OpenAPI（`scripts/check-traceability.ps1` OpenAPI 规则 50/50 通过；WS 按设计豁免）；`system_status_get` 已实现并经 `test_system_status.py` 覆盖；迁移头 `0015_system_state` 经真机 PG 迁移/回滚测试；host CLI 文档与 0015 布局同步（`deployment/scripts/README.md`） |

## 2. IMPLEMENTATION_PLAN §8 Definition of Done 逐项

| # | DoD | 状态 | 证据 |
| --- | --- | --- | --- |
| 1 | 用户在设计规定页面能看到/执行 | done | 设备详情/概览/告警/操作/文件/审计/用户页 + 类型页签；`/system` 系统状态页已交付（`SystemView.vue` + 顶栏 `SystemStatusChip`，M6T3b，spec 测试覆盖） |
| 2 | 前端只调用正式 OpenAPI | done | 前端类型由提交的 OpenAPI 生成；codegen 漂移测试；测试用 operationId 精确断言（test_openapi.py 等） |
| 3 | 后端只调用统一适配器 | done | 所有设备访问经适配器注册表；`app/adapters` 外无厂商协议引用（M6 门禁核对） |
| 4 | 数据和任务状态符合模型 | done | 状态机/分区/保留/append-only 测试（DATA_MODEL 契约） |
| 5 | 权限、确认、审计、错误和恢复完整 | done | M1T6 越权 12 项、高险预览/二次确认/幂等/互斥/核验/审计测试；错误码契约 |
| 6 | 自动化测试与真机证据满足测试策略 | done（自动化）/ blocked-with-evidence（真机） | 后端 2111 通过 / 78 跳过、前端 163 通过（M6T2b 连续两轮全绿）；M6T3b 全量实测：后端 2136 通过 / 78 跳过 / 0 失败、前端 25 文件 / 177 通过（含系统状态/维护模式/摄取心跳测试）；认证矩阵 306/306 `not_started` |
| 7 | 文档、ADR、追踪和发布说明一致 | done | 本文档、RELEASE_NOTES、KNOWN_LIMITATIONS、closeout.json 相互引用；追踪收口 51/51 全绿、无未决代码缺口；`system_status_get` 端点/页面/测试/文档一致（M6T3b）；真机认证仍为外部阻塞项（见第 1/3 节） |
| 8 | 无临时成功、未解释待办、占位按钮或绕过安全的调试入口 | done | `/system` 占位页已由真实实现替换（M6T3b）；M6T1 空态/错误态收口 + M6T2b 确定性门禁；fake 适配器 dev-only（ADR-032）不违反 |

## 3. TEST_STRATEGY §9 发布判定

逐项核对 51 条原始需求并运行真机矩阵严格门禁覆盖 306 个目标/能力组合。实际执行（2026-09-07）：

```text
# 非严格校验（结构）
pwsh -File scripts/check-hardware-certification.ps1 -MatrixPath tests/hardware-certification/matrix.json
Hardware certification validation passed.
Targets: 10
Expected coverage records: 306
Actual coverage records: 306
Release-ready mode: False

# 严格发布门禁
pwsh -File scripts/check-hardware-certification.ps1 -MatrixPath tests/hardware-certification/matrix.json -RequireReleaseReady
退出码 1；对每条记录报错（共 306 条，全部 not_started）：
- record HC-server.dell_idrac-SRV-MON-01-health.overall is not release-terminal: not_started
- record HC-server.dell_idrac-SRV-MON-01-health.overall lacks hardware_report_path
- record ... lacks executed_by
- record ... lacks valid executed_at
```

任何记录证据缺失、语义不一致、真机未认证或存在严重安全缺陷，0.1.0 均不可标记完成；不得用"后续补充"替代既定范围。结论：**0.1.0-rc.1，certification-pending；不是 0.1.0**。

## 4. 开放缺口与待决策项

1. M6T4 执行部署环境依赖的发布项（compose/SBOM/签名/摘要/离线包/升级演练 + python/npm 依赖漏洞扫描，见 KNOWN_LIMITATIONS §3）后复核第 1 节第 5 项。
2. M6T5 最终门禁：全量套件、DoD 复核与候选声明；现场真机认证完成后由发布负责人回填矩阵并升级为 0.1.0。

历史关闭项：M6T3 发现的 PLT-08 `GET /system/status` 缺口（无实现、无契约响应结构、无台账延期记录）已由 M6T3b 补齐交付（commit `cf375a9`）——本清单第 1 节第 6 项与第 2 节第 1/7/8 项随之转为 done。

## 5. 追加入口（正式发布前必须执行的命令）

```powershell
pwsh -File scripts/check-design.ps1                       # 基线契约
pwsh -File scripts/check-traceability.ps1                 # 追踪收口（51/51 全绿；OpenAPI 规则 50/50）
pwsh -File scripts/check-hardware-certification.ps1 `
  -MatrixPath tests/hardware-certification/matrix.json -RequireReleaseReady   # 真机严格门禁
```

（`check-traceability.ps1` 需先重新导出 OpenAPI：`backend\.venv\Scripts\python.exe -m app.tools.openapi_export`。）
