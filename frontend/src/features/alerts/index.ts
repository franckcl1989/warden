import { defineComponent, h } from 'vue';

// 当前问题页占位视图：M2（PLT-04）实现
export const AlertsView = defineComponent({
  name: 'AlertsView',
  setup: () => () => h('div', { class: 'placeholder-page' }, '当前问题（M2 实现）'),
});
