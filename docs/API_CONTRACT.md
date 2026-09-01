# Warden 0.1.0 API 契约

状态：`APPROVED_BASELINE`

## 1. 通用规则

- 基础路径：`/api/v1`；
- JSON 字段使用 snake_case；
- ID 使用 UUID 字符串；
- 时间使用 UTC ISO 8601，例如 `2026-09-01T08:00:00Z`；
- 生产环境前后端同源，所有变更请求要求会话 Cookie + `X-CSRF-Token`；
- 列表使用 `page`、`page_size`（默认 20，最大 100）、`sort`；
- 响应包含 `request_id`，服务端日志使用同一 ID；
- 设备交互不在普通请求中长时间同步等待，超过 2 秒的行为均返回任务或会话描述符；
- `contracts/http-api.json` 是端点/方法/operationId 白名单；OpenAPI 是请求响应 schema 的前后端契约。CI 导出 `openapi.json`、核对端点白名单并生成 TypeScript 类型；手写重复 DTO 禁止合并。

## 2. 错误格式

所有非 2xx 使用：

```json
{
  "error": {
    "code": "authentication_failed",
    "message": "设备认证失败",
    "details": {"stage": "device_probe"},
    "request_id": "0199..."
  }
}
```

`message` 可本地化，客户端逻辑只能依赖 `code`。允许的 code、HTTP 映射、`details` 白名单和重试分类只取 `contracts/error-codes.json`；未知异常统一转为不含 details 的 `internal_error` 并以 `request_id` 关联服务端日志。

通用状态码：

- `400` 参数或状态不合法；
- `401` 未登录/会话过期；
- `403` 权限不足；
- `404` 资源不存在或用户不可见；
- `409` 版本冲突、能力冲突、设备忙或幂等冲突；
- `412` `If-Match` 失败；
- `422` 业务参数验证失败；
- `429` 速率限制；
- `503` 必要依赖不可用，不能安全接受操作。

## 3. 认证与用户

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/auth/login` | 用户名/密码登录，设置 HttpOnly Cookie 并返回 CSRF token |
| `POST` | `/auth/logout` | 撤销当前会话 |
| `GET` | `/auth/me` | 当前用户、角色、权限和会话到期时间 |
| `POST` | `/auth/password` | 修改当前用户密码并撤销其他会话 |
| `POST` | `/auth/reauth` | 使用当前密码复验，在服务端记录当前会话 `reauthenticated_at` 并返回有效截止时间 |
| `GET/POST` | `/users` | 管理员查询/创建用户 |
| `GET/PATCH` | `/users/{id}` | 查询、禁用、启用、分配一个内置角色；不返回密码哈希 |
| `GET` | `/roles` | 返回内置角色和权限矩阵 |

不提供公开注册、忘记密码邮件和第三方 OAuth。高风险操作预览要求当前服务端会话在最近 5 分钟完成复验；不签发第二个可被盗用的 bearer token。复验失败使用平台认证错误，不得调用设备。

## 4. 设备

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/devices` | 设备列表和筛选 |
| `POST` | `/device-probes` | 在保存前测试连接并发现身份/能力；不持久化明文凭据 |
| `POST` | `/devices` | 保存设备和加密凭据；测试通过时可启用 |
| `GET` | `/devices/{id}` | 通用详情和版本号 |
| `PATCH` | `/devices/{id}` | 更新名称、连接配置、凭据或启用状态，要求 `If-Match` |
| `POST` | `/devices/{id}/probe` | 对已保存设备重新测试和发现能力 |
| `GET` | `/devices/{id}/capabilities` | 固有 `support_state`、动态 `runtime_availability`、来源需求和各自原因 |
| `GET` | `/devices/{id}/components` | 当前组件，按 kind/status 过滤 |
| `GET` | `/devices/{id}/events` | SEL、DSM、Trap、Syslog 等设备事件 |

0.1.0 不提供 `DELETE /devices/{id}`。

### 4.1 添加设备请求

```json
{
  "name": "core-switch-01",
  "device_type": "core_switch",
  "adapter_key": "switch.huawei_vrp_core",
  "management_endpoint": "10.0.0.10",
  "connection_config": {
    "snmp_version": "v3",
    "ssh_port": 22,
    "verify_tls": true
  },
  "credentials": {
    "snmp": {"username": "...", "auth_key": "...", "privacy_key": "..."},
    "ssh": {"username": "...", "password": "..."}
  },
  "enabled": true,
  "probe_token": "single-use-token"
}
```

响应绝不回显 `credentials`。无论探测成功或失败都会签发绑定探测结果和凭据摘要的 `probe_token`，有效 10 分钟：成功 token 可保存并启用，失败 token 只能保存为 `not_ready` 且 `enabled=false`。防止绕过连接测试直接启用。

更新管理地址、适配器、协议安全参数或凭据时，`PATCH /devices/{id}` 同样要求与新配置匹配的 probe token；仅修改名称或停用状态不要求重新探测。

## 5. 监控查询

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/overview` | 总览统计、需要关注设备和最近任务 |
| `GET` | `/devices/{id}/metrics/latest` | 指标当前值 |
| `GET` | `/devices/{id}/metrics/series` | 指标时间序列，指定 metric/component/from/to/resolution |
| `GET` | `/devices/{id}/collection-runs` | 采集历史和错误 |
| `GET` | `/alerts` | 当前或已恢复告警列表 |
| `GET` | `/alerts/{id}` | 告警证据、时间线和关联设备 |

时间序列分辨率固定：7 天内可用原始粒度，7–30 天使用 5 分钟聚合，超过 30 天至 180 天使用 1 小时聚合。客户端可请求更粗、不能请求超出保留期的细粒度；响应每条序列包含单位、质量和实际分辨率。枚举/布尔历史返回变化点与检查点，不做平均值。

0.1.0 不提供告警确认、关闭、派单或规则编排 API，也不根据 CPU、容量、错误计数、温度、功率等数值发明固定告警阈值。`/alerts` 只汇总机器契约允许的设备当前状态/告警、离线和数据过期；设备事件只通过事件 API 查询。

## 6. 操作预览与任务

### 6.1 两阶段提交

除 KVM/DSM/Web/SSH/Telnet 远程连接外，所有人工硬件任务使用相同两阶段 API。连接类能力使用第 7 节一次性 launch 契约，不进入副作用任务队列。

1. `POST /devices/{id}/operation-previews`
2. `POST /devices/{id}/operations`

预览请求：

```json
{
  "capability_key": "interface.admin.set",
  "parameters": {"interface_id": "GigabitEthernet0/0/12", "enabled": false}
}
```

预览响应：

```json
{
  "requirement_id": "CORE-ACT-02",
  "capability_key": "interface.admin.set",
  "risk_level": "high",
  "target": {"device_id": "...", "device_name": "core-switch-01"},
  "normalized_parameters": {"interface_id": "GigabitEthernet0/0/12", "enabled": false},
  "impact": "目标端口将停止转发，可能中断下联业务",
  "steps": ["读取当前状态", "执行 shutdown", "回读管理/运行状态"],
  "confirmation": {"kind": "type_device_name", "expected": "core-switch-01"},
  "preview_token": "signed-single-use-token",
  "expires_at": "2026-09-01T08:01:00Z"
}
```

提交请求：

```json
{
  "preview_token": "signed-single-use-token",
  "confirmation_text": "core-switch-01"
}
```

请求头必须包含唯一 `Idempotency-Key`。成功返回 `202 Accepted` 和 `operation_task`。服务端重新检查权限、设备版本、能力、互斥和令牌绑定；任何变化返回 `409 preview_stale`，要求重新预览。

参数 schema、风险、总超时、断连预期、互斥范围、取消策略和验证条件必须逐个来自 `contracts/operations.json` 的 `(requirement_id, capability_key)` profile。API 只用持久化 DeviceSnapshot 生成预览，不在请求内连接设备；Worker 在 fence 前执行实时只读 preflight。API 不接受适配器或前端附带的另一套定义。

### 6.2 任务查询

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/operations` | 任务列表，可按设备/需求/能力/用户/状态过滤 |
| `GET` | `/operations/{id}` | 任务、步骤、验证和产物 |
| `POST` | `/operations/{id}/cancel` | 仅 queued，或 running 但尚无 dispatch fence 且 profile 允许取消；fence 后返回 409 |
| `POST` | `/operations/{id}/verify` | 管理员对 verification_required 触发适配器回读，不重放动作 |
| `POST` | `/operations/{id}/resolve-verification` | 管理员根据可复核外部证据标记核验结论，必须填写证据类型/引用/理由并审计；仅口头判断不能标记成功 |

终态任务没有 retry API；重试必须重新创建预览和任务。

### 6.3 允许的能力键

操作 API 只接受 `contracts/capabilities.json` 中与 `*-ACT-*` 绑定且在 `contracts/operations.json` 有完全匹配 profile 的能力键。未知键或缺 profile 一律 `422 unsupported_operation`，即使适配器内部存在同名方法。

## 7. 远程连接

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/devices/{id}/launches` | 创建 KVM/DSM/Web 启动描述符或 SSH/Telnet 终端票据 |
| `GET` | `/launches/{id}` | 一次性读取启动描述符；外部 URL 不包含凭据 |
| `WS` | `/terminal/sessions/{ticket}` | SSH/Telnet 双向终端 |
| `POST` | `/terminal/sessions/{id}/close` | 主动关闭终端会话 |

launch 请求只接受 `capability_key` 和对应 profile 允许的参数。启动能力仍须对应 `SRV-ACT-03`、`NAS-ACT-02`、`CORE-ACT-03` 或 `ACCESS-ACT-04`。票据绑定用户、设备、能力、协议、来源会话和设备版本，60 秒未使用即失效；创建、握手成功/失败和关闭均写审计。外部 URL 使用 `Referrer-Policy: no-referrer`，不得把平台会话、设备密码或长期厂商令牌放入 URL。

## 8. 文件

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/files/uploads` | 创建上传会话，声明文件类型/大小/名称 |
| `PUT` | `/files/uploads/{id}/content` | 流式上传；服务端计算 SHA-256 |
| `POST` | `/files/uploads/{id}/complete` | 完成校验并转为 ready |
| `GET` | `/files` | 文件元数据列表 |
| `GET` | `/files/{id}` | 元数据和引用关系 |
| `GET` | `/files/{id}/download` | 权限校验后的流式下载 |
| `DELETE` | `/files/{id}` | 管理员逻辑删除；被运行中任务引用时返回 409 |
| `GET` | `/device-file-access/{ticket}` | 设备拉取固件/虚拟介质的受限流式端点，不使用用户会话 |

默认上限由类型控制：支持包/配置 5 GiB，固件 10 GiB，虚拟介质 50 GiB；部署可降低，不可在无容量检查时提高。

`device-file-access` 票据绑定文件、设备、来源 IP、用途、允许的 Range 请求和过期时间。虚拟介质票据在挂载任务期间有效、最长 24 小时；固件票据按操作计划时限有效。票据 URL 不写普通访问日志，任务结束/卸载后立即撤销。

## 9. 审计与系统

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/audit-logs` | 审计查询，只读 |
| `GET` | `/audit-logs/{id}` | 脱敏详情和关联任务/设备证据 |
| `GET` | `/system/status` | 受保护的组件状态和队列摘要 |
| `GET` | `/health/live` | 进程存活，不含敏感信息 |
| `GET` | `/health/ready` | 必要依赖就绪，仅返回组件级状态 |

维护模式由部署命令持久化设置；采集周期、Worker 并发、Trap/Syslog 监听和保留期属于只读部署配置。这些事项均不提供产品编辑 API；0.1.0 也不提供 Prometheus 指标端点。

## 10. SSE

`GET /events/stream`，事件示例：

```text
id: 0199...
event: operation.updated
data: {"entity_id":"...","version":7}
```

允许事件：`device.updated`、`alert.opened`、`alert.resolved`、`operation.updated`、`system.status_changed`。事件不含凭据、日志正文、指标批次或终端内容。

服务端保留最近 10 分钟事件 ID；客户端带 `Last-Event-ID` 重连。窗口外返回 `event: reset`，客户端重新拉取 REST 数据。

## 11. 权限与限流

- 登录：单 IP 5 次/分钟、单用户连续失败锁定；
- 普通读取：每会话 300 次/分钟；
- 设备探测：每用户 10 次/分钟；
- 操作预览：每用户 30 次/分钟；
- 操作提交：每用户 10 次/分钟，且受设备互斥；
- 文件上传：每用户最多 2 个并发；
- 终端：每用户最多 3 个、每设备最多 1 个交互会话。

权限不足返回 403；资源存在与否可能泄露敏感信息时统一返回 404。

## 12. 契约验证

- 后端 CI 导出 OpenAPI 并与仓库版本比较；未提交变化则失败；
- 前端从 OpenAPI 生成类型并执行 TypeScript 严格检查；
- API 契约测试覆盖成功、权限、冲突、错误码和脱敏；
- 所有人工操作端点检查 `requirement_id`、预览令牌、幂等键和审计；
- 禁止通过未文档化端点或通用“执行命令”接口绕过能力白名单。
