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
  ElTable,
  ElTableColumn,
  ElTag,
} from 'element-plus';
import { computed, onMounted, reactive, ref } from 'vue';
import { useRoute } from 'vue-router';

import AsyncState from '@/components/AsyncState.vue';
import CapabilityBadge from '@/components/CapabilityBadge.vue';
import DeviceIdentity from '@/components/DeviceIdentity.vue';
import ErrorDetail from '@/components/ErrorDetail.vue';
import HealthBadge from '@/components/HealthBadge.vue';
import ReachabilityBadge from '@/components/ReachabilityBadge.vue';
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
import { formatDateTime } from '@/lib/format';
import { PROBE_STAGE_LABELS, READINESS_LABELS, label } from '@/lib/labels';
import { useAuthStore } from '@/stores/auth';

// 设备详情（PLT-02 / PLT-03 基础：通用头部 + 能力清单 + 编辑/停用）。
const auth = useAuthStore();
const route = useRoute();

const deviceId = computed(() => String(route.params.id));

const state = ref<'loading' | 'ready' | 'error' | 'permission_denied' | 'not_found'>('loading');
const error = ref<ApiError | null>(null);
const device = ref<DeviceView | null>(null);
const capabilities = ref<CapabilityView[] | null>(null);

async function loadAll(): Promise<void> {
  state.value = 'loading';
  error.value = null;
  try {
    const [deviceResult, capabilitiesResult] = await Promise.all([
      request<DeviceView>(`/devices/${deviceId.value}`),
      request<CapabilitiesResponse>(`/devices/${deviceId.value}/capabilities`),
    ]);
    device.value = deviceResult;
    capabilities.value = capabilitiesResult.items;
    state.value = 'ready';
  } catch (caught) {
    error.value = caught as ApiError;
    if (error.value.code === 'permission_denied') {
      state.value = 'permission_denied';
    } else if (error.value.code === 'resource_not_found') {
      state.value = 'not_found';
    } else {
      state.value = 'error';
    }
  }
}

onMounted(() => {
  void loadAll();
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
  return (
    editForm.managementEndpoint.trim() !== device.value.management_endpoint ||
    editForm.port !== config['port'] ||
    editForm.protocol !== config['protocol'] ||
    editForm.verifyTls !== config['verify_tls'] ||
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
    if (editForm.tlsFingerprintSha256.trim()) {
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
      if (editForm.tlsFingerprintSha256.trim()) {
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

        <h2 class="device-detail__section-title">能力清单</h2>
        <el-table
          :data="capabilities ?? []"
          class="device-detail__cap-table"
          data-testid="capability-table"
        >
          <el-table-column prop="requirement_id" label="需求编号" width="140" />
          <el-table-column prop="requirement_title" label="需求" min-width="160" />
          <el-table-column prop="capability_key" label="能力键" min-width="220" />
          <el-table-column label="支持状态" width="120">
            <template #default="{ row }">
              <CapabilityBadge
                :support-state="row.support_state"
                :reason-code="row.reason_code"
                :detail="row.detail"
              />
            </template>
          </el-table-column>
          <el-table-column prop="discovery_method" label="适配路径" width="140" />
          <el-table-column label="最近核验" width="140">
            <template #default="{ row }">{{ formatDateTime(row.last_checked_at) }}</template>
          </el-table-column>
        </el-table>
        <p
          v-if="capabilities !== null && capabilities.length === 0"
          class="device-detail__empty-cap"
        >
          尚无能力发现结果，请先执行连接测试
        </p>
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
.device-detail__section-title {
  margin: 0 0 8px;
  font-size: 15px;
}
.device-detail__empty-cap {
  color: var(--warden-status-unknown);
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
