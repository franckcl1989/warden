# 业务组件层

本目录是 UI_SPEC §4 的业务组件层：页面不得散用 Element Plus 原始组件代替业务语义。

M0T5 只提供 `AsyncState.vue`（App 顶层加载状态壳）。其余组件按 UI_SPEC §4 在 M2 及以后实现：

- `DeviceIdentity`：名称、类别、厂商/型号、管理地址；
- `ReachabilityBadge`、`HealthBadge`、`FreshnessBadge`：可达性、健康、数据新鲜度徽标；
- `CapabilityButton`：能力状态、权限、禁用原因和需求编号；
- `MetricValue`、`MetricChart`：指标值与趋势图；
- `ComponentTable`、`EventTimeline`：组件当前态与设备事件；
- `OperationState`、`OperationTimeline`：操作任务状态与时间线；
- `RiskPreview`、`DeviceNameConfirmation`：高风险操作预览与设备名确认；
- `SensitiveFileLink`：敏感文件授权下载；
- `ErrorDetail`：稳定错误码、用户说明、请求 ID 和可行处理。

组件属性使用 OpenAPI 生成类型（`src/api/generated/`），禁止复制一套近似状态枚举。
