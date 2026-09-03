<script setup lang="ts">
import { ref } from 'vue';
import { useRouter } from 'vue-router';

import CapabilityButton from '@/components/CapabilityButton.vue';
import LaunchConsoleDialog from '@/features/devices/LaunchConsoleDialog.vue';
import OperationLaunchDialog from '@/features/operations/OperationLaunchDialog.vue';
import type { CapabilityView } from '@/api/types';
import { REQUIREMENTS } from '@/api/generated/contracts';
import { useAuthStore } from '@/stores/auth';

// 设备详情"操作"页签（PRODUCT_DESIGN §5.1/§5.2-5.5）：
// 按 *-ACT-* 需求分组展示能力按钮。console.* 连接类能力（M3T4 起
// console.kvm.open）走一次性 launch 流程（LaunchConsoleDialog → 新标签页
// 打开受控入口，ADR-006：不代理厂商页面）；其余操作能力进入两阶段预览流程
// （OperationLaunchDialog → 预览 → 设备名确认 → 202 → 任务详情）。
// 观察员无 operation.execute.* 权限时不展示操作页签内容（UI_SPEC §12）。
const props = defineProps<{
  deviceId: string;
  deviceName: string;
  capabilities: CapabilityView[];
}>();

const auth = useAuthStore();
const router = useRouter();

const dialogVisible = ref(false);
const launchDialogVisible = ref(false);
const activeKey = ref('');

const canExecute = (): boolean =>
  auth.permissions.some((permission) => permission.startsWith('operation.execute.'));

const isConsoleCapability = (capability: CapabilityView): boolean =>
  capability.capability_key.startsWith('console.');

const operationGroups = (): { requirementId: string; rows: CapabilityView[] }[] => {
  const groups = new Map<string, CapabilityView[]>();
  for (const capability of props.capabilities) {
    const requirement = REQUIREMENTS[capability.requirement_id];
    if (requirement === undefined || requirement.kind !== 'operation') {
      continue;
    }
    const list = groups.get(capability.requirement_id) ?? [];
    list.push(capability);
    groups.set(capability.requirement_id, list);
  }
  return [...groups.entries()].map(([requirementId, rows]) => ({ requirementId, rows }));
};

function openFlow(capabilityKey: string): void {
  const capability = props.capabilities.find((row) => row.capability_key === capabilityKey);
  if (capability === undefined || capability.support_state !== 'supported') {
    return;
  }
  activeKey.value = capabilityKey;
  if (isConsoleCapability(capability)) {
    launchDialogVisible.value = true;
    return;
  }
  dialogVisible.value = true;
}

function onCreated(taskId: string): void {
  void router.push({ name: 'operations-detail', params: { id: taskId } });
}

function activeCapability(): CapabilityView | undefined {
  return props.capabilities.find((row) => row.capability_key === activeKey.value);
}

function activeIsConsole(): boolean {
  const active = activeCapability();
  return active !== undefined && isConsoleCapability(active);
}
</script>

<template>
  <div class="operations-panel" data-testid="operations-panel">
    <template v-if="canExecute()">
      <p v-if="operationGroups().length === 0" class="operations-panel__note">
        该设备尚无操作能力发现记录，请先执行连接测试
      </p>
      <section
        v-for="group in operationGroups()"
        :key="group.requirementId"
        class="operations-panel__group"
        :data-testid="`operation-group-${group.requirementId}`"
      >
        <h3 class="operations-panel__title">
          <span class="operations-panel__requirement">{{ group.requirementId }}</span>
          {{ REQUIREMENTS[group.requirementId]?.title ?? '' }}
        </h3>
        <div class="operations-panel__buttons">
          <div
            v-for="row in group.rows"
            :key="row.capability_key"
            class="operations-panel__button-cell"
          >
            <CapabilityButton
              :capability-key="row.capability_key"
              :requirement-id="row.requirement_id"
              :requirement-title="REQUIREMENTS[row.requirement_id]?.title"
              :support-state="row.support_state"
              :reason-code="row.reason_code"
              :detail="row.detail"
              @click="openFlow(row.capability_key)"
            />
            <p class="operations-panel__discovery">
              适配路径：{{ row.discovery_method }} · {{ row.adapter_version }}
            </p>
          </div>
        </div>
      </section>
    </template>
    <p v-else class="operations-panel__note">当前账号无操作执行权限</p>

    <OperationLaunchDialog
      v-if="activeCapability() && !activeIsConsole()"
      v-model="dialogVisible"
      :device="{ id: deviceId, name: deviceName }"
      :capability-key="activeCapability()?.capability_key ?? ''"
      :requirement-id="activeCapability()?.requirement_id ?? ''"
      @created="onCreated"
    />
    <LaunchConsoleDialog
      v-if="activeCapability() && activeIsConsole()"
      v-model="launchDialogVisible"
      :device-id="deviceId"
      :capability-key="activeCapability()?.capability_key ?? ''"
      :requirement-id="activeCapability()?.requirement_id ?? ''"
    />
  </div>
</template>

<style scoped>
.operations-panel__note {
  color: var(--warden-status-unknown);
  font-size: 13px;
}
.operations-panel__group {
  margin-bottom: 22px;
}
.operations-panel__title {
  margin: 0 0 8px;
  font-size: 15px;
}
.operations-panel__requirement {
  font-family: monospace;
  color: var(--warden-status-unknown);
  margin-right: 10px;
  font-size: 12px;
}
.operations-panel__buttons {
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
}
.operations-panel__button-cell {
  max-width: 260px;
}
.operations-panel__discovery {
  margin: 2px 0 0;
  color: var(--warden-status-unknown);
  font-size: 11px;
}
</style>
