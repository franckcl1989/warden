import { defineComponent, h } from 'vue';

// 文件页占位视图：M2（PLT-06）实现
export const FilesView = defineComponent({
  name: 'FilesView',
  setup: () => () => h('div', { class: 'placeholder-page' }, '文件（M2 实现）'),
});
