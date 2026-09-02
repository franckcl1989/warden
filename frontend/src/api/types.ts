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
