# 硬件认证矩阵（tests/hardware-certification/matrix.json）

## 这是什么

`matrix.json` 是 0.1.0 实施阶段的真机认证索引产物：对 `contracts/hardware-targets.json` 中的
10 个认证目标 × 同名 `device_type` 需求的全部 metric / event / operation key，生成
`target_id + requirement_id + capability_key` 唯一覆盖记录。当前契约动态计算为 **306 条**，
数量完全由生成器从契约计算得出，不手工维护；`scripts/check-hardware-certification.ps1`
独立校验覆盖、归属和字段，`scripts/check-design.ps1` 同时校验契约自身的 306 总数。

设计阶段没有真机，因此**全部 306 条记录都是诚实的 `not_started`**：不伪造设备证据，
不把任何能力标记为通过。真机认证流程与证据规则见 `docs/HARDWARE_CERTIFICATION.md`。

## 生成方式

```powershell
pwsh -File scripts/generate-hardware-matrix.ps1 -GeneratedAt 2026-09-01T00:00:00Z
```

或等价入口：`pwsh -File scripts/tasks.ps1 matrix`、`make matrix`。

**时间戳约定**：`matrix` 任务与 CI drift 校验固定使用 `-GeneratedAt 2026-09-01T00:00:00Z`，
保证产物可复现（相同参数重新生成字节一致），drift 校验才能以 `git diff --exit-code`
捕获契约变更未同步到矩阵的情况。不传 `-GeneratedAt` 时使用当前 UTC 时间（临时查看用，
提交前请改用固定时间戳）。`generated_at` 与 `protocol_evidence[].captured_at` 表示该
可复现产物的生成参数，**不是**任何真机证据的采集时间——not_started 阶段本就不存在真机证据。

生成器结束后会自带运行一次 `scripts/check-hardware-certification.ps1` 自检，输出无效时
直接失败退出。

## not_started 占位约定（不可偏离）

| 字段 | 值 | 含义 |
| --- | --- | --- |
| `status` | `not_started` | 尚未形成自动化或真机结论 |
| `actual_device_model` | `exact_model` 目标：`declared_target`（如 `DS224+`、`S5732-H48XUM2CC`） | 该型号就是认证对象，不是伪造的证据 |
| `actual_device_model` | `management_family` 目标（5 个服务器）：`unrecorded` | 飞书未指定精确服务器型号，明示未记录 |
| `firmware_version` | `unrecorded` | 未记录 |
| `license_snapshot` | `[]` | 未记录许可快照 |
| `protocol_evidence` | 1 条 `{kind: protocol_document, path: contracts/capabilities.json, sha256: <该文件生成时真实 SHA-256>, captured_at: <生成时间戳>, sanitized: true}` | 契约文件是事实性的协议依据；不含任何设备响应 |
| `automated_tests` | `[]` | 尚无自动化报告 |
| `evidence` | `[]` | 尚无真机证据 |
| `operation_profile_id` | 仅 operation 记录：`{requirement_id}:{capability_key}` | 指向 `contracts/operations.json` 存在的 profile |
| `maintenance_window_ref` | 仅 operation 记录：`not_started-no-maintenance-window` | 尚无维护窗口引用 |
| `result_summary` | `未开始：尚无自动化测试或真机证据；…` | 明确、可复核的中文摘要 |

禁止把任何记录改为 `not_started` 之外的任何状态，也禁止把占位值替换成猜测的型号、
固件或设备证据。

## 如何补充真实证据

1. 按 `docs/HARDWARE_CERTIFICATION.md` 第 5/6 节在非生产设备上执行操作/监控验收；
2. 保留 `T-{requirement_id}` 自动化报告、脱敏真机响应 fixture、任务与审计导出；
3. 将记录状态改为对应终态，填写 `automated_tests` / `evidence` / `hardware_report_path` /
   `executed_at` / `executed_by`（operation 还要维护窗口引用）；
4. 运行日常检查：

```powershell
pwsh -File scripts/check-hardware-certification.ps1 -MatrixPath tests/hardware-certification/matrix.json
```

5. 全部记录达到终态后，才运行严格发布门禁：

```powershell
pwsh -File scripts/check-hardware-certification.ps1 -MatrixPath tests/hardware-certification/matrix.json -RequireReleaseReady
```

**在真机证据就绪之前，`-RequireReleaseReady` 必须保持失败（exit 1）**——这是诚实的
当前状态；任何让它“假装通过”的做法都违反发布门禁规则。

## 约束

- 修改 `contracts/`、`docs/`、`scripts/check-*.ps1` 后必须重新生成矩阵并重新过日常检查；
- 记录数量只能来自契约，不得在生成器或本文件外手工写死 306；
- 生成器输出必须是 UTF-8（无 BOM）、LF 换行，保证跨平台字节一致与 CI drift 校验稳定。
