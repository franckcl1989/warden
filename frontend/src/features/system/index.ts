import { defineComponent, h } from 'vue';

// 系统状态页占位视图：M2（PLT-08）实现
export const SystemView = defineComponent({
  name: 'SystemView',
  setup: () => () => h('div', { class: 'placeholder-page' }, '系统状态（M2 实现）'),
});
