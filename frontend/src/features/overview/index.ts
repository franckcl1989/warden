import { defineComponent, h } from 'vue';

// 总览占位视图：页面建设中，随 M2（PLT-03）交付
export const OverviewView = defineComponent({
  name: 'OverviewView',
  setup: () => () => h('div', { class: 'placeholder-page' }, '页面建设中（M2 交付）'),
});
