<script setup lang="ts">
import { ElTable, ElTableColumn } from 'element-plus';
import { onMounted, ref } from 'vue';

import AsyncState from '@/components/AsyncState.vue';
import CapabilityBadge from '@/components/CapabilityBadge.vue';
import MetricGroupsPanel from '@/features/devices/panels/MetricGroupsPanel.vue';
import SeverityBadge from '@/components/SeverityBadge.vue';
import type { ApiError } from '@/api/client';
import { request } from '@/api/client';
import type { AlertListItem, AlertsListResponse, CapabilityView, DeviceView } from '@/api/types';
import { formatDateTime } from '@/lib/format';
import { label, READINESS_LABELS } from '@/lib/labels';
import { listQueryString } from './common';

// 设备详情"概览"页签：当前问题（真实告警 API）+ 资产摘要 +
// 状态摘要指标（overviewIds）+ 能力清单（PRODUCT_DESIGN §5.1/§5.2-5.5）。
const props = defineProps<{
  deviceId: string;
  device: DeviceView;
  capabilities: CapabilityView[];
  overviewRequirementIds: string[];
}>();

const alertsState = ref<'loading' | 'ready' | 'error' | 'permission_denied'>('loading');
const alertsError = ref<ApiError | null>(null);
const alerts = ref<AlertListItem[]>([]);

async function loadAlerts(): Promise<void> {
  alertsState.value = 'loading';
  alertsError.value = null;
  try {
    const result = await request<AlertsListResponse>(
      `/alerts?${listQueryString({ page: 1, page_size: 50, device_id: props.deviceId, status: 'active' })}`,
    );
    alerts.value = result.items ?? [];
    alertsState.value = 'ready';
  } catch (caught) {
    alertsError.value = caught as ApiError;
    alertsState.value =
      alertsError.value.code === 'permission_denied' ? 'permission_denied' : 'error';
  }
}

onMounted(() => {
  void loadAlerts();
});
</script>

<template>
  <div class="device-overview" data-testid="device-overview">
    <section class="device-overview__section">
      <h3 class="device-overview__title">当前问题</h3>
      <AsyncState
        :state="alertsState"
        :error="alertsError"
        empty-text="当前无未恢复问题"
        @retry="loadAlerts"
      >
        <el-table v-if="alerts.length > 0" :data="alerts" row-key="id">
          <el-table-column label="严重级别" width="90">
            <template #default="{ row }">
              <SeverityBadge :severity="row.severity" />
            </template>
          </el-table-column>
          <el-table-column prop="title" label="问题" min-width="220" />
          <el-table-column label="规则" width="150">
            <template #default="{ row }">
              <code>{{ row.rule_key }}</code>
            </template>
          </el-table-column>
          <el-table-column label="首次发生" width="150">
            <template #default="{ row }">{{ formatDateTime(row.first_occurred_at) }}</template>
          </el-table-column>
          <el-table-column label="最近发生" width="150">
            <template #default="{ row }">{{ formatDateTime(row.last_occurred_at) }}</template>
          </el-table-column>
        </el-table>
      </AsyncState>
    </section>

    <section class="device-overview__section">
      <h3 class="device-overview__title">资产与采集</h3>
      <dl class="device-overview__asset">
        <div>
          <dt>厂商/型号</dt>
          <dd>{{ device.vendor ?? '—' }} {{ device.model ?? '' }}</dd>
        </div>
        <div>
          <dt>序列号</dt>
          <dd>{{ device.serial_number ?? '—' }}</dd>
        </div>
        <div>
          <dt>固件版本</dt>
          <dd>{{ device.firmware_version ?? '—' }}</dd>
        </div>
        <div>
          <dt>就绪状态</dt>
          <dd>{{ label(READINESS_LABELS, device.readiness) }}</dd>
        </div>
        <div>
          <dt>最近采集</dt>
          <dd>{{ formatDateTime(device.last_collected_at) }}</dd>
        </div>
        <div>
          <dt>连续失败/成功</dt>
          <dd>{{ device.consecutive_failures }} / {{ device.consecutive_successes }}</dd>
        </div>
      </dl>
    </section>

    <section class="device-overview__section">
      <h3 class="device-overview__title">状态摘要</h3>
      <MetricGroupsPanel
        :device-id="deviceId"
        :requirement-ids="overviewRequirementIds"
        :capabilities="capabilities"
      />
    </section>

    <section class="device-overview__section">
      <h3 class="device-overview__title">能力清单</h3>
      <el-table
        :data="capabilities ?? []"
        class="device-overview__cap-table"
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
      <p v-if="capabilities !== null && capabilities.length === 0" class="device-overview__note">
        尚无能力发现结果，请先执行连接测试
      </p>
    </section>
  </div>
</template>

<style scoped>
.device-overview__section {
  margin-bottom: 24px;
}
.device-overview__title {
  margin: 0 0 10px;
  font-size: 15px;
}
.device-overview__asset {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
  gap: 8px 24px;
  margin: 0;
  font-size: 13px;
}
.device-overview__asset div {
  display: flex;
  gap: 10px;
}
.device-overview__asset dt {
  color: var(--warden-status-unknown);
  width: 90px;
  flex-shrink: 0;
}
.device-overview__asset dd {
  margin: 0;
}
.device-overview__note {
  color: var(--warden-status-unknown);
}
</style>
