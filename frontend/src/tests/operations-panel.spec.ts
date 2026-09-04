import { createPinia, setActivePinia } from 'pinia';
import { mount } from '@vue/test-utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createMemoryHistory } from 'vue-router';

import OperationsPanel from '@/features/devices/panels/OperationsPanel.vue';
import { createAppRouter } from '@/router';
import { useAuthStore } from '@/stores/auth';

/**
 * 设备"操作"页签权限统一测试（M6T1，UI_SPEC §12：无权限操作不显示；
 * SECURITY §3.1：operation.execute.* 决定执行入口）：
 * - 观察员（无 operation.execute.*）看不到任何操作能力入口，只看到说明；
 * - 有执行权限时按能力支持状态渲染：supported 可点击、unsupported 禁用
 *   并显示原因；console.* 连接能力与其余操作共用同一权限门。
 */
function capabilityRow(
  capabilityKey: string,
  requirementId: string,
  supportState: string,
  extra: Record<string, unknown> = {},
) {
  return {
    capability_key: capabilityKey,
    requirement_id: requirementId,
    requirement_title: '',
    support_state: supportState,
    reason_code: null,
    detail: null,
    discovery_method: 'switch.huawei_vrp_core',
    adapter_version: 'simulator-verified',
    last_checked_at: '2026-09-04T08:00:00Z',
    ...extra,
  };
}

const ACT_CAPABILITIES = [
  capabilityRow('console.web.open', 'CORE-ACT-03', 'supported'),
  capabilityRow('power.cycle', 'SRV-ACT-01', 'supported'),
  capabilityRow('console.kvm.open', 'SRV-ACT-03', 'unsupported', {
    reason_code: 'model_unsupported',
    detail: '该型号固件不支持 KVM 功能',
  }),
];

const VIEWER_PERMISSIONS = ['device.read', 'monitor.read', 'operation.read'];
const EXECUTE_PERMISSIONS = [
  'device.read',
  'monitor.read',
  'operation.read',
  'operation.execute.low',
  'operation.execute.medium',
  'operation.execute.high',
];

function seedAuth(role: 'viewer' | 'operator', permissions: string[]): void {
  const auth = useAuthStore();
  auth.user = {
    id: 'u-1',
    username: role,
    display_name: role === 'viewer' ? '观察员' : '运维员',
    role,
    status: 'active',
    must_change_password: false,
    last_login_at: null,
    created_at: '2026-09-01T00:00:00Z',
    updated_at: '2026-09-01T00:00:00Z',
    version: 1,
  };
  auth.permissions = permissions;
}

async function mountPanel(role: 'viewer' | 'operator', permissions: string[]) {
  const pinia = createPinia();
  setActivePinia(pinia);
  seedAuth(role, permissions);
  const router = createAppRouter(createMemoryHistory());
  const wrapper = mount(OperationsPanel, {
    props: {
      deviceId: 'd-1',
      deviceName: 'switch-01',
      capabilities: ACT_CAPABILITIES as never,
    },
    global: { plugins: [pinia, router] },
  });
  return wrapper;
}

describe('设备详情操作页签权限（M6T1）', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('观察员看不到任何操作能力入口（普通操作与 console 连接均不显示）', async () => {
    const wrapper = await mountPanel('viewer', VIEWER_PERMISSIONS);
    expect(wrapper.findAll('[data-testid^="capability-"]').length).toBe(0);
    expect(wrapper.text()).toContain('当前账号无操作执行权限');
    // console 启动对话框与操作预览对话框都不存在
    expect(wrapper.find('[data-testid="launch-console-dialog"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="operation-flow"]').exists()).toBe(false);
    wrapper.unmount();
  });

  it('运维员可见能力网格：supported 可点击，unsupported 禁用并显示支持状态', async () => {
    const wrapper = await mountPanel('operator', EXECUTE_PERMISSIONS);
    const consoleButton = wrapper.get('[data-testid="capability-console.web.open"]');
    expect(consoleButton.attributes('disabled')).toBeUndefined();
    const powerButton = wrapper.get('[data-testid="capability-power.cycle"]');
    expect(powerButton.attributes('disabled')).toBeUndefined();
    const kvmButton = wrapper.get('[data-testid="capability-console.kvm.open"]');
    expect(kvmButton.attributes('disabled')).toBeDefined();
    // 禁用原因按 UI_SPEC §8 悬停展示；文字区展示需求编号与支持状态（不支持）
    expect(wrapper.text()).toContain('不支持');
    expect(wrapper.text()).toContain('SRV-ACT-01');
    expect(wrapper.text()).not.toContain('当前账号无操作执行权限');
    wrapper.unmount();
  });

  it('点击支持的 console 能力打开启动对话框（而不是操作预览）', async () => {
    const wrapper = await mountPanel('operator', EXECUTE_PERMISSIONS);
    await wrapper.get('[data-testid="capability-console.web.open"]').trigger('click');
    await flush();
    expect(wrapper.find('[data-testid="launch-console-dialog"]').exists()).toBe(true);
    wrapper.unmount();
  });
});

async function flush(): Promise<void> {
  for (let i = 0; i < 3; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}
