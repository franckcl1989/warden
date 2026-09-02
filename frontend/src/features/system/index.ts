import { defineComponent, h } from 'vue';

// 系统状态占位视图：页面建设中，随 M2（PLT-08）交付
export const SystemView = defineComponent({
  name: 'SystemView',
  setup: () => () => h('div', { class: 'placeholder-page' }, '页面建设中（M2 交付）'),
});
