import { defineComponent, h } from 'vue';

// 审计占位视图：页面建设中，随 M2（PLT-07）交付
export const AuditView = defineComponent({
  name: 'AuditView',
  setup: () => () => h('div', { class: 'placeholder-page' }, '页面建设中（M2 交付）'),
});
