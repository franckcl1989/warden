/* eslint-disable vue/one-component-per-file -- M1/M2 拆分为独立视图文件 */
import { defineComponent, h } from 'vue';

// 设备页占位视图：M1（PLT-02）实现设备接入与列表；M2（PLT-03）实现详情

function placeholder(text: string) {
  return () => h('div', { class: 'placeholder-page' }, text);
}

export const DevicesListView = defineComponent({
  name: 'DevicesListView',
  setup: placeholder('设备列表（M1 实现）'),
});

export const DevicesNewView = defineComponent({
  name: 'DevicesNewView',
  setup: placeholder('添加设备（M1 实现）'),
});

export const DevicesDetailView = defineComponent({
  name: 'DevicesDetailView',
  setup: placeholder('设备详情（M2 实现）'),
});
