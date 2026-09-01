import { defineComponent, h } from 'vue';

// 审计页占位视图：M2（PLT-07）实现
export const AuditView = defineComponent({
  name: 'AuditView',
  setup: () => () => h('div', { class: 'placeholder-page' }, '审计（M2 实现）'),
});
