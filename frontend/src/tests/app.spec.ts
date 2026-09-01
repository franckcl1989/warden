import { mount } from '@vue/test-utils';
import { createPinia } from 'pinia';
import { describe, expect, it } from 'vitest';
import { createMemoryHistory } from 'vue-router';

import App from '@/App.vue';
import { createAppRouter } from '@/router';

describe('App 外壳', () => {
  it('通过 router-view 渲染 Element Plus 包裹的占位页面', async () => {
    const router = createAppRouter(createMemoryHistory());
    await router.push('/login');
    await router.isReady();
    const wrapper = mount(App, {
      global: { plugins: [createPinia(), router] },
    });
    expect(wrapper.text()).toContain('登录');
    expect(wrapper.findComponent({ name: 'ElConfigProvider' }).exists()).toBe(true);
    await router.push('/overview');
    await wrapper.vm.$nextTick();
    expect(wrapper.text()).toContain('总览');
  });
});
