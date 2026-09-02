<script setup lang="ts">
import {
  ElButton,
  ElCard,
  ElCheckbox,
  ElDescriptions,
  ElDescriptionsItem,
  ElForm,
  ElFormItem,
  ElInput,
  ElInputNumber,
  ElOption,
  ElSelect,
  ElSteps,
  ElStep,
} from 'element-plus';
import { computed, reactive, ref } from 'vue';
import { useRouter } from 'vue-router';

import AsyncState from '@/components/AsyncState.vue';
import CapabilityBadge from '@/components/CapabilityBadge.vue';
import ErrorDetail from '@/components/ErrorDetail.vue';
import type { ApiError } from '@/api/client';
import { request } from '@/api/client';
import type { DeviceProbeResponse, DeviceView } from '@/api/types';
import { DEVICE_TYPES } from '@/api/generated/contracts';
import { ADAPTER_LABELS, DEVICE_TYPE_LABELS, PROBE_STAGE_LABELS, label } from '@/lib/labels';

// 添加设备向导（PLT-02，PRODUCT_DESIGN §4.2 六步，单页流程）。
const router = useRouter();

const ADAPTER_KEY = 'fake.simple';
const DEV_ADAPTER_TYPES = new Set(['server']);

const step = ref(0);
const deviceType = ref<string | null>(null);
const adapterKey = ref<string>(ADAPTER_KEY);
const name = ref('');
const managementEndpoint = ref('');
const port = ref<number | null>(null);
const connectionConfig = reactive({
  protocol: 'https',
  verifyTls: true,
  tlsFingerprintSha256: '',
  failTls: false,
  failCredentials: false,
});
const credentials = reactive({ username: '', password: '' });

const probing = ref(false);
const probeError = ref<ApiError | null>(null);
const probe = ref<DeviceProbeResponse | null>(null);

const saving = ref(false);
const saveError = ref<ApiError | null>(null);

const currentTypeSupported = computed(
  () => deviceType.value !== null && DEV_ADAPTER_TYPES.has(deviceType.value),
);

const stages = computed(() => probe.value?.stages ?? []);

function step1Valid(): boolean {
  return currentTypeSupported.value && deviceType.value !== null;
}

function step2Valid(): boolean {
  if (!name.value.trim()) return false;
  const endpoint = managementEndpoint.value.trim();
  if (!endpoint) return false;
  if (
    /\s/.test(endpoint) ||
    endpoint.includes('://') ||
    endpoint.includes('/') ||
    endpoint.includes('@')
  ) {
    return false;
  }
  if (port.value !== null && (port.value < 1 || port.value > 65535)) return false;
  return true;
}

function step3Valid(): boolean {
  return credentials.username.trim().length > 0 && credentials.password.length > 0;
}

function probePayload(): Record<string, unknown> {
  const config: Record<string, unknown> = {
    protocol: connectionConfig.protocol,
    verify_tls: connectionConfig.verifyTls,
  };
  if (connectionConfig.tlsFingerprintSha256.trim()) {
    config.tls_fingerprint_sha256 = connectionConfig.tlsFingerprintSha256.trim();
  }
  if (connectionConfig.failTls) config.fail_tls = true;
  if (connectionConfig.failCredentials) config.fail_credentials = true;
  const body: Record<string, unknown> = {
    device_type: deviceType.value,
    adapter_key: adapterKey.value,
    management_endpoint: managementEndpoint.value.trim(),
    connection_config: config,
    credentials: {
      username: credentials.username.trim(),
      password: credentials.password,
    },
  };
  if (port.value !== null) body.port = port.value;
  return body;
}

async function runProbe(): Promise<void> {
  probing.value = true;
  probeError.value = null;
  try {
    probe.value = await request<DeviceProbeResponse>('/device-probes', {
      method: 'POST',
      body: probePayload(),
    });
  } catch (caught) {
    probeError.value = caught as ApiError;
    probe.value = null;
  } finally {
    probing.value = false;
  }
}

async function saveDevice(): Promise<void> {
  if (probe.value === null) return;
  saving.value = true;
  saveError.value = null;
  try {
    const body: Record<string, unknown> = {
      ...probePayload(),
      name: name.value.trim(),
      enabled: probe.value.ok,
      probe_token: probe.value.probe_token,
    };
    const device = await request<DeviceView>('/devices', { method: 'POST', body });
    await router.replace({ name: 'device-detail', params: { id: device.id } });
  } catch (caught) {
    saveError.value = caught as ApiError;
  } finally {
    saving.value = false;
  }
}
</script>

<template>
  <div class="devices-new">
    <el-steps :active="step" finish-status="success" align-center class="devices-new__steps">
      <el-step title="类别与适配器" />
      <el-step title="基本信息" />
      <el-step title="协议与凭据" />
      <el-step title="连接测试" />
      <el-step title="发现结果" />
      <el-step title="保存" />
    </el-steps>

    <el-card class="devices-new__card">
      <!-- 第 1 步：类别与适配器 -->
      <div v-if="step === 0">
        <el-form label-width="96px">
          <el-form-item label="设备类别">
            <el-select
              v-model="deviceType"
              placeholder="选择设备类别"
              style="width: 280px"
              data-testid="device-type"
            >
              <el-option
                v-for="type in DEVICE_TYPES"
                :key="type"
                :value="type"
                :label="label(DEVICE_TYPE_LABELS, type)"
              />
            </el-select>
          </el-form-item>
          <el-form-item label="适配器">
            <el-select
              v-model="adapterKey"
              style="width: 280px"
              :disabled="!currentTypeSupported"
              data-testid="adapter-key"
            >
              <el-option :value="ADAPTER_KEY" :label="ADAPTER_LABELS[ADAPTER_KEY]" />
            </el-select>
          </el-form-item>
          <p v-if="deviceType !== null && !currentTypeSupported" class="devices-new__notice">
            该类别暂无可用适配器，真实适配器随 M3/M4/M5 真机交付加入
          </p>
        </el-form>
      </div>

      <!-- 第 2 步：基本信息 -->
      <div v-else-if="step === 1">
        <el-form label-width="96px">
          <el-form-item label="设备名称">
            <el-input v-model="name" placeholder="例如：server-01" data-testid="device-name" />
          </el-form-item>
          <el-form-item label="管理地址">
            <el-input
              v-model="managementEndpoint"
              placeholder="主机名或 IP，不含协议与路径"
              data-testid="management-endpoint"
            />
          </el-form-item>
          <el-form-item label="端口">
            <el-input-number
              v-model="port"
              :min="1"
              :max="65535"
              :controls="false"
              placeholder="默认端口"
            />
          </el-form-item>
        </el-form>
      </div>

      <!-- 第 3 步：协议与凭据 -->
      <div v-else-if="step === 2">
        <el-form label-width="96px">
          <el-form-item label="协议">
            <el-select v-model="connectionConfig.protocol" style="width: 200px">
              <el-option value="https" label="HTTPS" />
            </el-select>
          </el-form-item>
          <el-form-item label="校验 TLS">
            <el-checkbox v-model="connectionConfig.verifyTls">启用证书校验</el-checkbox>
          </el-form-item>
          <el-form-item v-if="connectionConfig.verifyTls" label="TLS 指纹">
            <el-input
              v-model="connectionConfig.tlsFingerprintSha256"
              placeholder="SHA-256 指纹（64 位十六进制，可留空首次确认）"
            />
          </el-form-item>
          <el-form-item label="用户名">
            <el-input
              v-model="credentials.username"
              autocomplete="off"
              data-testid="credential-username"
            />
          </el-form-item>
          <el-form-item label="密码">
            <el-input
              v-model="credentials.password"
              type="password"
              show-password
              autocomplete="new-password"
              data-testid="credential-password"
            />
          </el-form-item>
          <el-form-item label="开发用">
            <div class="devices-new__dev">
              <el-checkbox v-model="connectionConfig.failTls"
                >模拟 TLS 失败（测试适配器）</el-checkbox
              >
              <el-checkbox v-model="connectionConfig.failCredentials"
                >模拟认证失败（测试适配器）</el-checkbox
              >
            </div>
          </el-form-item>
        </el-form>
        <p class="devices-new__hint">凭据只发送给平台用于连接测试与加密保存，绝不回显</p>
      </div>

      <!-- 第 4 步：连接测试 -->
      <div v-else-if="step === 3">
        <div class="devices-new__probe-actions">
          <el-button type="primary" :loading="probing" data-testid="run-probe" @click="runProbe">
            {{ probe ? '重新连接测试' : '开始连接测试' }}
          </el-button>
        </div>
        <ErrorDetail v-if="probeError" :error="probeError" class="devices-new__error" />
        <ul v-if="probe" class="devices-new__stages" data-testid="probe-stages">
          <li
            v-for="stage in stages"
            :key="stage.stage"
            class="devices-new__stage"
            :class="stage.ok ? 'devices-new__stage--ok' : 'devices-new__stage--fail'"
          >
            <span class="devices-new__stage-name">{{
              label(PROBE_STAGE_LABELS, stage.stage)
            }}</span>
            <span class="devices-new__stage-result">{{ stage.ok ? '通过' : '失败' }}</span>
            <span v-if="!stage.ok && stage.error_code" class="devices-new__stage-code">
              错误码：{{ stage.error_code }}
            </span>
            <span v-if="stage.detail" class="devices-new__stage-detail">{{ stage.detail }}</span>
          </li>
        </ul>
      </div>

      <!-- 第 5 步：发现结果 -->
      <div v-else-if="step === 4">
        <AsyncState v-if="probe === null" :state="'empty'" :empty-text="'尚未执行连接测试'" />
        <template v-else-if="probe.discovery">
          <el-descriptions :column="2" border>
            <el-descriptions-item label="厂商">{{ probe.discovery.vendor }}</el-descriptions-item>
            <el-descriptions-item label="型号">{{ probe.discovery.model }}</el-descriptions-item>
            <el-descriptions-item label="序列号">
              {{ probe.discovery.serial_number ?? '—' }}
            </el-descriptions-item>
            <el-descriptions-item label="固件版本">
              {{ probe.discovery.firmware_version ?? '—' }}
            </el-descriptions-item>
          </el-descriptions>
          <h3 class="devices-new__cap-title">能力清单</h3>
          <el-table
            :data="probe.discovery.capabilities"
            class="devices-new__cap-table"
            data-testid="capability-table"
          >
            <el-table-column prop="requirement_id" label="需求编号" width="140" />
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
          </el-table>
        </template>
        <div v-else class="devices-new__notice" data-testid="probe-failed-notice">
          连接测试未通过，无法发现设备身份与能力。仍可保存为未就绪（不会启用采集），
          后续可在详情页重新连接测试。
        </div>
      </div>

      <!-- 第 6 步：保存 -->
      <div v-else>
        <p class="devices-new__summary">
          设备：{{ name.trim() }}（{{ label(DEVICE_TYPE_LABELS, deviceType) }}） · 管理地址：{{
            managementEndpoint.trim()
          }}
        </p>
        <p
          v-if="probe?.ok"
          class="devices-new__notice devices-new__notice--ok"
          data-testid="save-ready-notice"
        >
          连接测试通过，保存后设备为就绪状态
        </p>
        <p v-else class="devices-new__notice" data-testid="save-notready-notice">
          连接测试未通过：设备将保存为未就绪且不会启用采集，可在详情页重新测试后启用
        </p>
        <ErrorDetail v-if="saveError" :error="saveError" class="devices-new__error" />
        <div class="devices-new__save-actions">
          <el-button type="primary" :loading="saving" data-testid="save-device" @click="saveDevice">
            保存设备
          </el-button>
        </div>
      </div>

      <div class="devices-new__nav">
        <el-button v-if="step > 0" data-testid="prev-step" @click="step -= 1">上一步</el-button>
        <el-button
          v-if="step < 5"
          type="primary"
          :disabled="
            (!step1Valid() && step === 0) ||
            (!step2Valid() && step === 1) ||
            (!step3Valid() && step === 2) ||
            (probe === null && step >= 3)
          "
          data-testid="next-step"
          @click="step += 1"
        >
          下一步
        </el-button>
      </div>
    </el-card>
  </div>
</template>

<style scoped>
.devices-new__steps {
  margin-bottom: 24px;
}
.devices-new__notice {
  margin: 12px 0;
  padding: 8px 12px;
  border-radius: 4px;
  background: var(--el-color-warning-light-9);
  color: var(--el-color-warning);
}
.devices-new__notice--ok {
  background: var(--el-color-success-light-9);
  color: var(--el-color-success);
}
.devices-new__hint {
  color: var(--warden-status-unknown);
  font-size: 12px;
}
.devices-new__dev {
  display: flex;
  gap: 16px;
}
.devices-new__probe-actions,
.devices-new__save-actions {
  margin-bottom: 16px;
}
.devices-new__error {
  margin-bottom: 12px;
}
.devices-new__stages {
  list-style: none;
  margin: 0;
  padding: 0;
}
.devices-new__stage {
  display: flex;
  gap: 12px;
  align-items: baseline;
  padding: 8px 0;
  border-bottom: 1px solid var(--el-border-color-lighter);
}
.devices-new__stage-name {
  width: 140px;
  font-weight: 600;
}
.devices-new__stage--ok .devices-new__stage-result {
  color: var(--warden-status-healthy);
}
.devices-new__stage--fail .devices-new__stage-result {
  color: var(--warden-status-critical);
}
.devices-new__stage-code {
  color: var(--warden-status-critical);
  font-family: monospace;
  font-size: 12px;
}
.devices-new__stage-detail {
  color: var(--warden-status-unknown);
  font-size: 13px;
}
.devices-new__cap-title {
  margin: 20px 0 8px;
  font-size: 15px;
}
.devices-new__summary {
  margin: 0 0 12px;
}
.devices-new__nav {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  margin-top: 20px;
}
</style>
