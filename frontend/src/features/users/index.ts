import { defineComponent, h } from 'vue';

// 用户与角色页占位视图：M1（PLT-01）实现
export const UsersView = defineComponent({
  name: 'UsersView',
  setup: () => () => h('div', { class: 'placeholder-page' }, '用户与角色（M1 实现）'),
});
