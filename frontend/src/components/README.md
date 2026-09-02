# 业务组件层

本目录是 UI_SPEC §4 的业务组件层：页面不得散用 Element Plus 原始组件代替业务语义。

## M1（PLT-01/PLT-02）已实现

- `AsyncState.vue`：loading/empty/error/permission_denied 四种状态壳，支持错误详情与重试；
- `ErrorDetail.vue`：稳定错误码、中文说明、请求 ID 和用户可执行的下一步（UI_SPEC §10）；
- `ReachabilityBadge.vue`：unknown/online/offline 可达性徽标（GLOSSARY 独立维度）；
- `HealthBadge.vue`：unknown/healthy/warning/critical 健康徽标，可展示"最后已知健康"；
- `CapabilityBadge.vue`：supported/unsupported/not_configured 支持状态 + 原因悬停；
- `DeviceIdentity.vue`：名称、类别、厂商/型号、管理地址；
- `PaginationBar.vue`：默认 20 条/页，可选 50/100（UI_SPEC §5）；
- `AppShell.vue`：UI_SPEC §2 全局框架（224px 可收起侧栏 + 顶栏用户菜单）；
- `ChangePasswordDialog.vue`：修改当前用户密码对话框。

## M2 及以后实现（UI_SPEC §4 其余组件）

- `FreshnessBadge`：数据新鲜度徽标；
- `CapabilityButton`：能力状态、权限、禁用原因和需求编号；
- `MetricValue`、`MetricChart`：指标值与趋势图；
- `ComponentTable`、`EventTimeline`：组件当前态与设备事件；
- `OperationState`、`OperationTimeline`：操作任务状态与时间线；
- `RiskPreview`、`DeviceNameConfirmation`：高风险操作预览与设备名确认；
- `SensitiveFileLink`：敏感文件授权下载。

组件属性使用 OpenAPI 生成类型（`src/api/generated/`），禁止复制一套近似状态枚举。
