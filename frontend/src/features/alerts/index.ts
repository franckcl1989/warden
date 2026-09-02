import { defineComponent, h } from 'vue';

// 当前问题占位视图：页面建设中，随 M2（PLT-04）交付
export const AlertsView = defineComponent({
  name: 'AlertsView',
  setup: () => () => h('div', { class: 'placeholder-page' }, '页面建设中（M2 交付）'),
});
