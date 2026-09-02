<script setup lang="ts">
import { DEVICE_TYPE_LABELS, label } from '@/lib/labels';

// UI_SPEC §4 DeviceIdentity：名称、类别、厂商/型号、管理地址。
defineProps<{
  name: string;
  deviceType: string;
  vendor: string | null;
  model: string | null;
  managementEndpoint: string;
}>();
</script>

<template>
  <div class="device-identity">
    <h2 class="device-identity__name">{{ name }}</h2>
    <p class="device-identity__meta">
      {{ label(DEVICE_TYPE_LABELS, deviceType) }}
      <span v-if="vendor || model"> · {{ vendor ?? '—' }} {{ model ?? '' }}</span>
      <span class="device-identity__endpoint"> · 管理地址：{{ managementEndpoint }}</span>
    </p>
  </div>
</template>

<style scoped>
.device-identity__name {
  margin: 0 0 4px;
  font-size: 20px;
  font-weight: 600;
}
.device-identity__meta {
  margin: 0;
  color: var(--warden-status-unknown);
  font-size: 13px;
}
.device-identity__endpoint {
  font-family: monospace;
}
</style>
