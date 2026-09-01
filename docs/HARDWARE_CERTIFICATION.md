# Warden 0.1.0 真机认证规范

状态：`APPROVED_BASELINE`  
适用版本：0.1.0

## 1. 目标

真机认证用于证明某个**精确实际型号 + 固件版本 + 许可组合**上的一个能力真实可用或真实不支持。它不是设备支持清单的手工备注，也不能被模拟器、截图、按钮存在或厂商同系列其他型号资料替代。

本规范与以下机器文件共同构成发布门禁：

- `contracts/hardware-targets.json`：0.1.0 的 10 个认证目标及适配器边界；
- `contracts/hardware-certification.schema.json`：认证矩阵记录格式；
- `tests/hardware-certification/matrix.json`：实施阶段生成的实际证据索引，不在设计阶段伪造；
- `scripts/check-hardware-certification.ps1`：覆盖率、归属和发布状态校验器。

## 2. 最小覆盖单元

覆盖主键固定为：

```text
target_id + requirement_id + capability_key
```

一个需求含多个指标或动作时必须逐键认证，不能用一条“需求通过”掩盖部分能力未测。按当前 10 个目标和能力目录，完整矩阵应有 **306 个唯一记录**；校验器从契约动态计算该数量，不信任手工总数。

服务器源需求只给出 iDRAC/iBMC/XCC 管理族而没有精确服务器型号，因此五个服务器目标的 `declared_target` 只表示待认证管理族。认证时必须填写 `actual_device_model`，不得把某一台服务器的通过结果外推为整个管理族全部型号都支持。NAS 和交换机按飞书指定型号认证。

## 3. 证据规则

每条候选记录必须包含：

- 需求编号、能力键和 metric/event/operation 类型；
- 契约中的 adapter key，操作还必须有精确 operation profile ID；
- 实际设备型号、固件和许可快照；
- 精确版本协议依据：官方资料、设备 API discovery、MIB/YANG/CLI 参考或脱敏真机响应；
- 对应 `T-{requirement_id}` 自动化报告与 SHA-256；
- 真机报告、执行人、执行时间和脱敏证据索引；
- 人工功能的维护窗口引用；
- 明确、可复核的结果摘要。

证据文件不直接嵌入矩阵，只保存工作区相对路径和 SHA-256。所有证据必须先脱敏；凭据、Cookie、token、序列号原文、网络拓扑和支持包敏感正文不得进入代码仓库。确需保留的敏感原件放在加密证据库，矩阵仅记录脱敏副本或受控引用。

## 4. 状态与准入

| 状态 | 含义 | 可否通过发布门禁 |
| --- | --- | --- |
| `not_started` | 尚未形成自动化或真机结论 | 否 |
| `automated_passed` | 自动化通过，真机未完成 | 否 |
| `hardware_passed` | 真机执行和回读满足契约成功条件 | 是 |
| `unsupported_with_evidence` | 精确组合有不支持证据，且用户书面接受 | 有条件允许 |
| `failed` | 行为错误、证据矛盾或验收失败 | 否 |

`unsupported_with_evidence` 不是开发捷径，必须同时具备：

1. 设备原生响应/UI/CLI 或精确厂商资料证明；
2. 平台正确显示 `unsupported` 或 `not_configured`，不显示可执行成功入口；
3. `user_acceptance_ref` 指向用户明确接受的范围处理决定；
4. 不存在通过已认证标准协议或已授权厂商接口实现该能力的遗漏路径。

任何记录都不得用 `experimental` 通过发布门禁。experimental 只能作为运行时支持声明，认证矩阵仍保持未通过终态。

## 5. 操作验收步骤

每个 operation profile 在非生产设备和已批准维护窗口内按以下顺序执行：

1. 保存型号、固件、许可、协议配置和操作前状态；
2. 运行 snapshot plan，核对参数、风险、冲突范围和预期影响；
3. 运行 Worker live preflight，证明前置条件仍成立且没有副作用；
4. 通过正式 API 完成权限、复验、确认、幂等和任务持久化；
5. 记录 dispatch fence、设备响应或设备 job ID；
6. 按 profile 的 verification 策略回读，不以 HTTP/SSH 命令返回即判成功；
7. 对照设备原生 UI/CLI/日志；
8. 导出任务、审计、回读和自动化报告，脱敏并计算 SHA-256；
9. 断连或超时不能证明最终状态时记录 `failed` 或产品任务 `verification_required`，不得补写 `hardware_passed`。

电源、升级、配置恢复、端口、PoE 和虚拟介质必须验证成功路径及至少一个安全可构造的失败前置条件。禁止通过断电等可能损坏设备的方式制造失败。

## 6. 监控验收步骤

每个 metric/event key 必须：

1. 对照设备原生 UI/CLI/API 确认值、单位、组件归属和时间；
2. 覆盖正常值，以及真实可得或安全构造的未知/异常/缺字段条件；
3. 验证 unsupported、not_configured、temporarily_unavailable、stale/expired 和 observation error 不被写成 0/normal；
4. 验证数值序列、状态变化点、事件去重和告警策略符合机器契约；
5. 将脱敏真机响应转成 fixture，并保留实际型号、固件、采集日期和原证据散列。

## 7. 执行与发布命令

实施阶段先生成符合 schema 的 `tests/hardware-certification/matrix.json`，日常检查覆盖和字段：

```powershell
pwsh -File scripts/check-hardware-certification.ps1 -MatrixPath tests/hardware-certification/matrix.json
```

发布候选必须执行严格门禁：

```powershell
pwsh -File scripts/check-hardware-certification.ps1 -MatrixPath tests/hardware-certification/matrix.json -RequireReleaseReady
```

两条命令都必须保留完整输出。设计阶段没有真机和证据，所以不创建虚假的 matrix，也不运行发布通过声明。

## 8. 证据冲突处理

- 真机行为与飞书功能目标冲突：停止该能力，记录 proposed ADR 和风险，不改变来源语义；
- 真机行为与厂商资料冲突：保留双方证据，按该精确固件的实际行为处理，支持范围不得外推；
- 同型号不同固件行为不同：拆分认证组合，不覆盖旧记录；
- 证据散列不匹配、缺失或未脱敏：该记录无效；
- 后续固件升级：原记录保持不可变，为新固件建立新认证矩阵/报告并重新过门禁。
