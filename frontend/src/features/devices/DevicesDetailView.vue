<script setup lang="ts">
import {
  ElButton,
  ElCheckbox,
  ElDialog,
  ElForm,
  ElFormItem,
  ElInput,
  ElInputNumber,
  ElMessage,
  ElMessageBox,
  ElOption,
  ElRadio,
  ElRadioGroup,
  ElSelect,
  ElTabPane,
  ElTabs,
  ElTag,
} from 'element-plus';
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import AsyncState from '@/components/AsyncState.vue';
import DeviceIdentity from '@/components/DeviceIdentity.vue';
import ErrorDetail from '@/components/ErrorDetail.vue';
import HealthBadge from '@/components/HealthBadge.vue';
import ReachabilityBadge from '@/components/ReachabilityBadge.vue';
import BackupStatusPanel from '@/features/devices/panels/BackupStatusPanel.vue';
import CollectionRunsPanel from '@/features/devices/panels/CollectionRunsPanel.vue';
import ComponentsPanel from '@/features/devices/panels/ComponentsPanel.vue';
import EventsPanel from '@/features/devices/panels/EventsPanel.vue';
import MetricGroupsPanel from '@/features/devices/panels/MetricGroupsPanel.vue';
import OperationsPanel from '@/features/devices/panels/OperationsPanel.vue';
import OverviewPanel from '@/features/devices/panels/OverviewPanel.vue';
import PoePanel from '@/features/devices/panels/PoePanel.vue';
import PortsPanel from '@/features/devices/panels/PortsPanel.vue';
import { deviceTabsFor } from '@/features/devices/deviceTabs';
import type { ApiError } from '@/api/client';
import { request } from '@/api/client';
import type {
  CapabilitiesResponse,
  CapabilityView,
  DeviceProbeExistingResponse,
  DeviceProbeResponse,
  DeviceView,
  ProbeStageView,
} from '@/api/types';
import { registerCacheEntry } from '@/lib/query-cache';
import { formatDateTime } from '@/lib/format';
import { PROBE_STAGE_LABELS, READINESS_LABELS, label } from '@/lib/labels';
import { useAuthStore } from '@/stores/auth';

// 设备详情（PLT-02/PLT-03）：通用头部 + 按 device_type 的监控页签
// （PRODUCT_DESIGN §5.1-5.5，配置见 deviceTabs.ts）。
const auth = useAuthStore();
const route = useRoute();
const router = useRouter();

const deviceId = computed(() => String(route.params.id));

const state = ref<'loading' | 'ready' | 'error' | 'permission_denied' | 'not_found'>('loading');
const error = ref<ApiError | null>(null);
const device = ref<DeviceView | null>(null);
const capabilities = ref<CapabilityView[] | null>(null);

const activeTab = ref<string>('overview');

const tabs = computed(() => (device.value ? deviceTabsFor(device.value.device_type) : []));

function tabFromQuery(): string | null {
  const query = route.query['tab'];
  return typeof query === 'string' && query !== '' ? query : null;
}

async function loadAll(silent = false): Promise<void> {
  if (!silent) {
    state.value = 'loading';
  }
  error.value = null;
  try {
    const [deviceResult, capabilitiesResult] = await Promise.all([
      request<DeviceView>(`/devices/${deviceId.value}`),
      request<CapabilitiesResponse>(`/devices/${deviceId.value}/capabilities`),
    ]);
    device.value = deviceResult;
    capabilities.value = capabilitiesResult.items;
    // 页签写入 URL query（UI_SPEC §2），设备类别变化时回落到概览
    const requested = tabFromQuery();
    const valid = tabs.value.some((tab) => tab.id === requested);
    activeTab.value = valid && requested !== null ? requested : 'overview';
    state.value = 'ready';
  } catch (caught) {
    error.value = caught as ApiError;
    if (!silent) {
      if (error.value.code === 'permission_denied') {
        state.value = 'permission_denied';
      } else if (error.value.code === 'resource_not_found') {
        state.value = 'not_found';
      } else {
        state.value = 'error';
      }
    }
  }
}

function onTabChange(tabName: string | number): void {
  const name = String(tabName);
  if (name === tabFromQuery()) {
    return;
  }
  void router.replace({ query: { ...route.query, tab: name } });
}

// SSE：device.updated → 静默重取设备与能力（UI_SPEC §11 局部刷新不清空旧数据；
// 不置全页 loading，避免骨架屏闪烁与页签重挂载）
let unregisterCache: (() => void) | null = null;

watch(
  () => state.value,
  (next) => {
    if (next === 'ready' && unregisterCache === null) {
      unregisterCache = registerCacheEntry({
        kind: 'device-detail',
        id: deviceId.value,
        refetch: () => void loadAll(true),
      });
    }
  },
);

onMounted(() => {
  void loadAll();
});

onBeforeUnmount(() => {
  unregisterCache?.();
  unregisterCache = null;
});

// ---------- 停用 / 启用 ----------
async function toggleEnabled(): Promise<void> {
  if (device.value === null) return;
  const disabling = device.value.enabled;
  try {
    await ElMessageBox.confirm(
      disabling
        ? '停用后停止采集并禁止新操作，历史数据、文件与审计保留。确认停用？'
        : '确认启用该设备？',
      disabling ? '停用设备' : '启用设备',
      { type: 'warning', confirmButtonText: '确认', cancelButtonText: '取消' },
    );
  } catch {
    return;
  }
  try {
    const updated = await request<DeviceView>(`/devices/${deviceId.value}`, {
      method: 'PATCH',
      headers: { 'If-Match': String(device.value.version) },
      body: { enabled: !disabling },
    });
    device.value = updated;
    ElMessage.success(disabling ? '设备已停用' : '设备已启用');
  } catch (caught) {
    ElMessage.error(`操作失败：${(caught as ApiError).message}`);
  }
}

// ---------- 重新连接测试（对已保存配置） ----------
const probeDialogVisible = ref(false);
const reprobing = ref(false);
const probeResult = ref<DeviceProbeExistingResponse | null>(null);

async function runReProbe(): Promise<void> {
  reprobing.value = true;
  probeResult.value = null;
  try {
    probeResult.value = await request<DeviceProbeExistingResponse>(
      `/devices/${deviceId.value}/probe`,
      { method: 'POST' },
    );
  } finally {
    reprobing.value = false;
    await loadAll();
  }
}

// ---------- 编辑（含重新探测门禁） ----------
const editVisible = ref(false);
const editError = ref<ApiError | null>(null);
const savingEdit = ref(false);

const editForm = reactive({
  name: '',
  managementEndpoint: '',
  port: 443,
  protocol: 'https',
  verifyTls: true,
  tlsFingerprintSha256: '',
  credentialMode: 'keep' as 'keep' | 'replace',
  credentialUsername: '',
  credentialPassword: '',
});

const editProbe = ref<DeviceProbeResponse | null>(null);
const editProbing = ref(false);
const editProbeError = ref<ApiError | null>(null);

function openEdit(): void {
  if (device.value === null) return;
  const config = device.value.connection_config as Record<string, unknown>;
  editForm.name = device.value.name;
  editForm.managementEndpoint = device.value.management_endpoint;
  editForm.port = typeof config['port'] === 'number' ? config['port'] : 443;
  editForm.protocol = typeof config['protocol'] === 'string' ? config['protocol'] : 'https';
  editForm.verifyTls = typeof config['verify_tls'] === 'boolean' ? config['verify_tls'] : true;
  editForm.tlsFingerprintSha256 =
    typeof config['tls_fingerprint_sha256'] === 'string' ? config['tls_fingerprint_sha256'] : '';
  if (!editForm.verifyTls) {
    editForm.tlsFingerprintSha256 = '';
  }
  editForm.credentialMode = 'keep';
  editForm.credentialUsername = '';
  editForm.credentialPassword = '';
  editProbe.value = null;
  editProbeError.value = null;
  editError.value = null;
  editVisible.value = true;
}

function configChanged(): boolean {
  if (device.value === null) return false;
  const config = device.value.connection_config as Record<string, unknown>;
  const storedPort = typeof config['port'] === 'number' ? config['port'] : 443;
  const storedProtocol = typeof config['protocol'] === 'string' ? config['protocol'] : 'https';
  const storedVerifyTls = typeof config['verify_tls'] === 'boolean' ? config['verify_tls'] : true;
  return (
    editForm.managementEndpoint.trim() !== device.value.management_endpoint ||
    editForm.port !== storedPort ||
    editForm.protocol !== storedProtocol ||
    editForm.verifyTls !== storedVerifyTls ||
    editForm.tlsFingerprintSha256.trim() !== (config['tls_fingerprint_sha256'] ?? '')
  );
}

const securityRelevantChanged = computed(
  () => configChanged() || editForm.credentialMode === 'replace',
);

function editConfigPayload(): Record<string, unknown> {
  return {
    protocol: editForm.protocol,
    port: editForm.port,
    verify_tls: editForm.verifyTls,
  } as Record<string, unknown>;
}

async function runEditProbe(): Promise<void> {
  editProbing.value = true;
  editProbeError.value = null;
  try {
    const body: Record<string, unknown> = {
      device_type: device.value?.device_type,
      adapter_key: device.value?.adapter_key,
      management_endpoint: editForm.managementEndpoint.trim(),
      connection_config: editConfigPayload(),
      credentials:
        editForm.credentialMode === 'replace'
          ? {
              username: editForm.credentialUsername.trim(),
              password: editForm.credentialPassword,
            }
          : { username: '', password: '' },
    };
    if (editForm.verifyTls && editForm.tlsFingerprintSha256.trim()) {
      (body.connection_config as Record<string, unknown>)['tls_fingerprint_sha256'] =
        editForm.tlsFingerprintSha256.trim();
    }
    editProbe.value = await request<DeviceProbeResponse>('/device-probes', {
      method: 'POST',
      body,
    });
  } catch (caught) {
    editProbeError.value = caught as ApiError;
    editProbe.value = null;
  } finally {
    editProbing.value = false;
  }
}

async function saveEdit(): Promise<void> {
  if (device.value === null) return;
  savingEdit.value = true;
  editError.value = null;
  try {
    const body: Record<string, unknown> = { name: editForm.name.trim() };
    if (securityRelevantChanged.value) {
      body.management_endpoint = editForm.managementEndpoint.trim();
      body.connection_config = editConfigPayload();
      if (editForm.verifyTls && editForm.tlsFingerprintSha256.trim()) {
        (body.connection_config as Record<string, unknown>)['tls_fingerprint_sha256'] =
          editForm.tlsFingerprintSha256.trim();
      }
      if (editForm.credentialMode === 'replace') {
        body.credentials = {
          username: editForm.credentialUsername.trim(),
          password: editForm.credentialPassword,
        };
      }
      if (editProbe.value === null || !editProbe.value.ok) {
        ElMessage.warning('连接配置已修改，保存前必须重新连接测试');
        return;
      }
      body.probe_token = editProbe.value.probe_token;
    }
    const updated = await request<DeviceView>(`/devices/${deviceId.value}`, {
      method: 'PATCH',
      headers: { 'If-Match': String(device.value.version) },
      body,
    });
    device.value = updated;
    editVisible.value = false;
    ElMessage.success('设备已更新');
    await loadAll();
  } catch (caught) {
    editError.value = caught as ApiError;
  } finally {
    savingEdit.value = false;
  }
}

function editStages(): ProbeStageView[] {
  return editProbe.value?.stages ?? [];
}

function closeEdit(): void {
  editVisible.value = false;
}
</script>

<template>
  <div class="device-detail">
    <AsyncState :state="state" :error="error">
      <template v-if="device">
        <div class="device-detail__header">
          <DeviceIdentity
            :name="device.name"
            :device-type="device.device_type"
            :vendor="device.vendor"
            :model="device.model"
            :management-endpoint="device.management_endpoint"
          />
          <div class="device-detail__badges">
            <ReachabilityBadge :reachability="device.reachability" />
            <HealthBadge :health="device.health" :last-known-health="device.last_known_health" />
            <el-tag size="small" :type="device.readiness === 'ready' ? 'success' : 'info'">
              {{ label(READINESS_LABELS, device.readiness) }}
            </el-tag>
            <el-tag size="small" :type="device.enabled ? 'success' : 'info'">
              {{ device.enabled ? '已启用' : '已停用' }}
            </el-tag>
          </div>
          <div class="device-detail__meta">
            <span>序列号：{{ device.serial_number ?? '—' }}</span>
            <span>固件版本：{{ device.firmware_version ?? '—' }}</span>
            <span>最近采集：{{ formatDateTime(device.last_collected_at) }}</span>
          </div>
          <div v-if="auth.isAdmin" class="device-detail__actions">
            <el-button data-testid="edit-device" @click="openEdit">编辑</el-button>
            <el-button data-testid="reprobe-device" @click="probeDialogVisible = true">
              重新连接测试
            </el-button>
            <el-button
              :type="device.enabled ? 'danger' : 'success'"
              data-testid="toggle-enabled"
              @click="toggleEnabled"
            >
              {{ device.enabled ? '停用' : '启用' }}
            </el-button>
          </div>
        </div>

        <el-tabs
          v-model="activeTab"
          class="device-detail__tabs"
          data-testid="device-tabs"
          @tab-change="onTabChange"
        >
          <el-tab-pane v-for="tab in tabs" :key="tab.id" :name="tab.id" :label="tab.title" lazy>
            <div v-if="activeTab === tab.id" class="device-detail__tab-body">
              <template v-for="(section, index) in tab.sections" :key="`${tab.id}-${index}`">
                <OverviewPanel
                  v-if="section.kind === 'overview'"
                  :device-id="device.id"
                  :device="device"
                  :capabilities="capabilities ?? []"
                  :overview-requirement-ids="section.requirementIds ?? []"
                />
                <MetricGroupsPanel
                  v-else-if="section.kind === 'metric-groups'"
                  :device-id="device.id"
                  :requirement-ids="section.requirementIds ?? []"
                  :capabilities="capabilities ?? []"
                />
                <ComponentsPanel
                  v-else-if="section.kind === 'components'"
                  :device-id="device.id"
                  :kinds="section.kinds"
                />
                <PortsPanel
                  v-else-if="section.kind === 'ports'"
                  :device-id="device.id"
                  :requirement-ids="section.requirementIds ?? []"
                  :kinds="section.kinds"
                  :capabilities="capabilities ?? []"
                />
                <PoePanel
                  v-else-if="section.kind === 'poe'"
                  :device-id="device.id"
                  :requirement-ids="section.requirementIds ?? []"
                  :kinds="section.kinds"
                  :capabilities="capabilities ?? []"
                />
                <EventsPanel
                  v-else-if="section.kind === 'events'"
                  :device-id="device.id"
                  :event-types="section.eventTypes"
                  :capabilities="capabilities ?? []"
                />
                <BackupStatusPanel
                  v-else-if="section.kind === 'backup-status'"
                  :device-id="device.id"
                  :device-name="device.name"
                  :capabilities="capabilities ?? []"
                />
                <CollectionRunsPanel
                  v-else-if="section.kind === 'collection-runs'"
                  :device-id="device.id"
                />
                <OperationsPanel
                  v-else-if="section.kind === 'operations'"
                  :device-id="device.id"
                  :device-name="device.name"
                  :capabilities="capabilities ?? []"
                />
              </template>
            </div>
          </el-tab-pane>
        </el-tabs>
      </template>
    </AsyncState>

    <!-- 重新连接测试 -->
    <el-dialog v-model="probeDialogVisible" title="重新连接测试" width="560px" @open="runReProbe">
      <AsyncState :state="reprobing ? 'loading' : 'ready'">
        <ul v-if="probeResult" class="device-detail__stages" data-testid="reprobe-stages">
          <li
            v-for="stage in probeResult.stages"
            :key="stage.stage"
            class="device-detail__stage"
            :class="stage.ok ? 'device-detail__stage--ok' : 'device-detail__stage--fail'"
          >
            <span>{{ label(PROBE_STAGE_LABELS, stage.stage) }}</span>
            <span>{{ stage.ok ? '通过' : '失败' }}</span>
            <span v-if="stage.error_code">{{ stage.error_code }}</span>
            <span v-if="stage.detail">{{ stage.detail }}</span>
          </li>
        </ul>
      </AsyncState>
      <template #footer>
        <el-button @click="probeDialogVisible = false">关闭</el-button>
      </template>
    </el-dialog>

    <!-- 编辑 -->
    <el-dialog v-model="editVisible" title="编辑设备" width="560px" :close-on-click-modal="false">
      <ErrorDetail v-if="editError" :error="editError" class="device-detail__dialog-error" />
      <el-form label-width="110px">
        <el-form-item label="设备名称">
          <el-input v-model="editForm.name" data-testid="edit-name" />
        </el-form-item>
        <el-form-item label="管理地址">
          <el-input v-model="editForm.managementEndpoint" data-testid="edit-endpoint" />
        </el-form-item>
        <el-form-item label="端口">
          <el-input-number v-model="editForm.port" :min="1" :max="65535" :controls="false" />
        </el-form-item>
        <el-form-item label="协议">
          <el-select v-model="editForm.protocol" style="width: 160px">
            <el-option value="https" label="HTTPS" />
          </el-select>
        </el-form-item>
        <el-form-item label="校验 TLS">
          <el-checkbox v-model="editForm.verifyTls">启用证书校验</el-checkbox>
        </el-form-item>
        <el-form-item v-if="editForm.verifyTls" label="TLS 指纹">
          <el-input
            v-model="editForm.tlsFingerprintSha256"
            placeholder="SHA-256 指纹（64 位十六进制）"
          />
        </el-form-item>
        <el-form-item label="凭据">
          <el-radio-group v-model="editForm.credentialMode" data-testid="credential-mode">
            <el-radio value="keep">保持不变</el-radio>
            <el-radio value="replace">替换</el-radio>
          </el-radio-group>
        </el-form-item>
        <template v-if="editForm.credentialMode === 'replace'">
          <el-form-item label="用户名">
            <el-input v-model="editForm.credentialUsername" autocomplete="off" />
          </el-form-item>
          <el-form-item label="密码">
            <el-input
              v-model="editForm.credentialPassword"
              type="password"
              show-password
              autocomplete="new-password"
            />
          </el-form-item>
        </template>
      </el-form>

      <div
        v-if="securityRelevantChanged"
        class="device-detail__reprobe-gate"
        data-testid="reprobe-gate"
      >
        <p>连接配置或凭据已修改，保存前必须重新连接测试</p>
        <ErrorDetail
          v-if="editProbeError"
          :error="editProbeError"
          class="device-detail__dialog-error"
        />
        <el-button :loading="editProbing" data-testid="edit-run-probe" @click="runEditProbe">
          连接测试
        </el-button>
        <ul v-if="editProbe" class="device-detail__stages" data-testid="edit-probe-stages">
          <li
            v-for="stage in editStages()"
            :key="stage.stage"
            class="device-detail__stage"
            :class="stage.ok ? 'device-detail__stage--ok' : 'device-detail__stage--fail'"
          >
            <span>{{ label(PROBE_STAGE_LABELS, stage.stage) }}</span>
            <span>{{ stage.ok ? '通过' : '失败' }}</span>
            <span v-if="stage.error_code">{{ stage.error_code }}</span>
          </li>
        </ul>
        <p v-if="editProbe && !editProbe.ok" class="device-detail__reprobe-fail">
          连接测试未通过，新配置不会被保存
        </p>
      </div>

      <template #footer>
        <el-button @click="closeEdit">取消</el-button>
        <el-button
          type="primary"
          :loading="savingEdit"
          :disabled="securityRelevantChanged && (editProbe === null || !editProbe.ok)"
          data-testid="save-edit"
          @click="saveEdit"
        >
          保存
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.device-detail__header {
  display: flex;
  align-items: flex-start;
  flex-wrap: wrap;
  gap: 16px;
  padding: 8px 0 20px;
}
.device-detail__header > *:first-child {
  flex: 1;
  min-width: 260px;
}
.device-detail__badges {
  display: flex;
  gap: 8px;
  align-items: center;
}
.device-detail__meta {
  width: 100%;
  display: flex;
  gap: 20px;
  color: var(--warden-status-unknown);
  font-size: 13px;
}
.device-detail__actions {
  display: flex;
  gap: 8px;
}
.device-detail__tabs {
  margin-top: 4px;
}
.device-detail__tab-body {
  padding: 16px 0;
}
.device-detail__stages {
  list-style: none;
  margin: 0;
  padding: 0;
}
.device-detail__stage {
  display: flex;
  gap: 12px;
  padding: 6px 0;
  border-bottom: 1px solid var(--el-border-color-lighter);
  font-size: 13px;
}
.device-detail__stage--ok {
  color: var(--warden-status-healthy);
}
.device-detail__stage--fail {
  color: var(--warden-status-critical);
}
.device-detail__dialog-error {
  margin-bottom: 12px;
}
.device-detail__reprobe-gate {
  border: 1px solid var(--el-border-color);
  border-radius: 4px;
  padding: 12px;
  margin-bottom: 8px;
}
.device-detail__reprobe-gate p {
  margin: 0 0 8px;
}
.device-detail__reprobe-fail {
  color: var(--warden-status-critical);
  font-size: 13px;
}
</style>
