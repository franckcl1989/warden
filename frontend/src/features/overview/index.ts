import { defineComponent, h } from 'vue';

// 总览页占位视图：M2（PLT-03）实现
export const OverviewView = defineComponent({
  name: 'OverviewView',
  setup: () => () => h('div', { class: 'placeholder-page' }, '总览（M2 实现）'),
});
