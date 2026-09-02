<script setup lang="ts">
import { ElPagination } from 'element-plus';

// UI_SPEC §5 列表规范：默认 20 条/页，可选 50/100。
const props = withDefaults(
  defineProps<{
    page: number;
    pageSize: number;
    total: number;
    pageSizes?: number[];
  }>(),
  { pageSizes: () => [20, 50, 100] },
);

const emit = defineEmits<{
  'update:page': [page: number];
  'update:pageSize': [pageSize: number];
}>();

function onCurrentChange(page: number): void {
  emit('update:page', page);
}

function onSizeChange(pageSize: number): void {
  emit('update:pageSize', pageSize);
  emit('update:page', 1);
}
</script>

<template>
  <el-pagination
    class="pagination-bar"
    :current-page="props.page"
    :page-size="props.pageSize"
    :page-sizes="props.pageSizes"
    :total="props.total"
    layout="total, sizes, prev, pager, next, jumper"
    :pager-count="7"
    background
    @current-change="onCurrentChange"
    @size-change="onSizeChange"
  />
</template>

<style scoped>
.pagination-bar {
  justify-content: flex-end;
  margin-top: 16px;
}
</style>
