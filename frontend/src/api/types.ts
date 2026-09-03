/**
 * 从生成 OpenAPI 重导出的请求/响应类型别名。
 * 只重导出，不复制结构（rules: 禁止手写第二套 DTO）；结构一律来自
 * frontend/src/api/generated/openapi.ts。
 */
import type { components } from '@/api/generated/openapi';

type Schemas = components['schemas'];

export type UserView = Schemas['UserView'];
export type LoginResponse = Schemas['LoginResponse'];
export type MeResponse = Schemas['MeResponse'];
export type ReauthResponse = Schemas['ReauthResponse'];
export type ChangePasswordRequest = Schemas['ChangePasswordRequest'];
export type UserListResponse = Schemas['UserListResponse'];
export type UserCreateRequest = Schemas['UserCreateRequest'];
export type UserUpdateRequest = Schemas['UserUpdateRequest'];
export type DeviceView = Schemas['DeviceView'];
export type DeviceListResponse = Schemas['DeviceListResponse'];
export type DeviceProbeRequest = Schemas['DeviceProbeRequest'];
export type DeviceProbeResponse = Schemas['DeviceProbeResponse'];
export type DeviceProbeExistingResponse = Schemas['DeviceProbeExistingResponse'];
export type DeviceCreateRequest = Schemas['DeviceCreateRequest'];
export type DeviceUpdateRequest = Schemas['DeviceUpdateRequest'];
export type CapabilitiesResponse = Schemas['CapabilitiesResponse'];
export type CapabilityView = Schemas['CapabilityView'];
export type ProbeStageView = Schemas['ProbeStageView'];
export type DiscoveryView = Schemas['DiscoveryView'];
export type CapabilitySupportView = Schemas['CapabilitySupportView'];

export type OverviewResponse = Schemas['OverviewResponse'];
export type OverviewStats = Schemas['OverviewStats'];
export type DeviceTypeSummary = Schemas['DeviceTypeSummary'];
export type AttentionItem = Schemas['AttentionItem'];
export type AttentionProblem = Schemas['AttentionProblem'];

export type AlertListItem = Schemas['AlertListItem'];
export type AlertDetailItem = Schemas['AlertDetailItem'];
export type AlertsListResponse = Schemas['AlertsListResponse'];

export type LatestMetricItem = Schemas['LatestMetricItem'];
export type LatestComponentGroup = Schemas['LatestComponentGroup'];
export type DeviceMetricsLatestResponse = Schemas['DeviceMetricsLatestResponse'];
export type DeviceMetricsSeriesResponse = Schemas['DeviceMetricsSeriesResponse'];
export type SeriesPointView = Schemas['SeriesPointView'];

export type ComponentView = Schemas['ComponentView'];
export type ComponentRef = Schemas['ComponentRef'];
export type DeviceComponentsListResponse = Schemas['DeviceComponentsListResponse'];
export type DeviceEventView = Schemas['DeviceEventView'];
export type DeviceEventsListResponse = Schemas['DeviceEventsListResponse'];
export type CollectionRunView = Schemas['CollectionRunView'];
export type DeviceCollectionRunsListResponse = Schemas['DeviceCollectionRunsListResponse'];

export type OperationPreviewRequest = Schemas['OperationPreviewRequest'];
export type OperationPreviewResponse = Schemas['OperationPreviewResponse'];
export type OperationSubmitRequest = Schemas['OperationSubmitRequest'];
export type OperationResolveRequest = Schemas['OperationResolveRequest'];
export type OperationTaskView = Schemas['OperationTaskView'];
export type OperationTaskDetail = Schemas['OperationTaskDetail'];
export type OperationEventView = Schemas['OperationEventView'];
export type OperationsListResponse = Schemas['OperationsListResponse'];

export type LaunchCreateResponse = Schemas['LaunchCreateResponse'];
export type LaunchConsumeResponse = Schemas['LaunchConsumeResponse'];

export type FileView = Schemas['FileView'];
export type FileListResponse = Schemas['FileListResponse'];
export type FileUploadCreateRequest = Schemas['FileUploadCreateRequest'];
export type FileUploadContentView = Schemas['FileUploadContentView'];
export type FileLinkView = Schemas['FileLinkView'];

export type AuditLogListItem = Schemas['AuditLogListItem'];
export type AuditLogDetailItem = Schemas['AuditLogDetailItem'];
export type AuditLogListResponse = Schemas['AuditLogListResponse'];
