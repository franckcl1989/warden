# 业务组件层

本目录是 UI_SPEC §4 的业务组件层：页面不得散用 Element Plus 原始组件代替业务语义。

## 已实现

### M1（PLT-01/PLT-02）

- `AsyncState.vue`：loading/empty/error/permission_denied 四种状态壳，支持错误详情与重试；
- `ErrorDetail.vue`：稳定错误码、中文说明、请求 ID 和用户可执行的下一步（UI_SPEC §10）；
- `ReachabilityBadge.vue`：unknown/online/offline 可达性徽标（GLOSSARY 独立维度）；
- `HealthBadge.vue`：unknown/healthy/warning/critical 健康徽标，可展示"最后已知健康"；
- `CapabilityBadge.vue`：supported/unsupported/not_configured 支持状态 + 原因悬停；
- `DeviceIdentity.vue`：名称、类别、厂商/型号、管理地址；
- `PaginationBar.vue`：默认 20 条/页，可选 50/100（UI_SPEC §5）；
- `AppShell.vue`：UI_SPEC §2 全局框架（224px 可收起侧栏 + 顶栏用户菜单 + 实时连接指示）；
- `ChangePasswordDialog.vue`：修改当前用户密码对话框。

### M2（PLT-03/04/05/06/07/09 监控界面）

- `FreshnessBadge.vue`：数据新鲜度徽标（unknown/fresh/stale/expired，PRODUCT_DESIGN §6.3）；
- `SeverityBadge.vue`：当前问题/设备事件严重级别徽标；
- `OperationState.vue`：操作任务状态徽标（verification_required 使用独立紫色，UI_SPEC §3）；
- `CapabilityButton.vue`：能力状态、权限、禁用原因和需求编号（UI_SPEC §8，发起真实预览流程）；
- `MetricValue.vue`：指标值 + 单位 + 质量 + 观测时间 + 新鲜度徽标；
- `MetricChart.vue`：ECharts 趋势图（时间范围 1h–180d、实际分辨率、缺口留空、
  最多 8 条序列、无自造参考线、文本摘要无障碍，UI_SPEC §7.3/§12）；
- `ComponentTable.vue`：组件当前态列表（kind/status/native_id/properties）；
- `PortTable.vue`（M5T5）：端口/部件行表（名称与关键状态列固定，每行最新
  指标 chips —— bps 速率带单位 bit/s；观测缺失如实显示“尚无观测”）；
- `EventTimeline.vue`：设备事件时间线（SEL/DSM 日志/Trap/Syslog）；
- `OperationTimeline.vue`：任务时间线（平台已接收/已发送设备/等待设备/验证/终态）；
- `SensitiveFileLink.vue`：敏感文件授权下载链接（无权限显示明确原因）。

组件属性使用 OpenAPI 生成类型（`src/api/generated/`），禁止复制一套近似状态枚举。

## 实时层（M2T7，UI_SPEC §11）

- `src/api/events.ts`：SSE 订阅层（EventSource 同源 /events/stream、事件分发、
  断线降级 15 秒轮询、恢复停止轮询、reset 全量重取信号）；
- `src/lib/query-cache.ts`：轻量查询缓存（fetch 键 → 重取闭包，无重型库）；
- `src/stores/realtime.ts`：实时 store，把 SSE 事件映射为查询缓存失效
  （operation/alerts/device/system/reset）。
