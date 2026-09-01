<script setup lang="ts">
import { ElConfigProvider } from 'element-plus';

import AsyncState from '@/components/AsyncState.vue';
</script>

<template>
  <el-config-provider>
    <AsyncState :state="'idle'">
      <RouterView />
    </AsyncState>
  </el-config-provider>
</template>
