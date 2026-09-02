import { defineComponent, h } from 'vue';

// 文件占位视图：页面建设中，随 M2（PLT-06）交付
export const FilesView = defineComponent({
  name: 'FilesView',
  setup: () => () => h('div', { class: 'placeholder-page' }, '页面建设中（M2 交付）'),
});
