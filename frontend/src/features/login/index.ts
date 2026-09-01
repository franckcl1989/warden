import { defineComponent, h } from 'vue';

// 登录页占位视图：M1（PLT-01）实现
export const LoginView = defineComponent({
  name: 'LoginView',
  setup: () => () => h('div', { class: 'placeholder-page' }, '登录（M1 实现）'),
});
