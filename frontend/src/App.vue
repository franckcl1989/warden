<script setup lang="ts">
import { ElConfigProvider } from 'element-plus';
import { computed } from 'vue';
import { useRoute } from 'vue-router';

import AppShell from '@/components/AppShell.vue';

const route = useRoute();
const isPublicPage = computed(() => route.meta.public === true);
</script>

<template>
  <el-config-provider>
    <AppShell v-if="!isPublicPage">
      <RouterView />
    </AppShell>
    <RouterView v-else />
  </el-config-provider>
</template>
