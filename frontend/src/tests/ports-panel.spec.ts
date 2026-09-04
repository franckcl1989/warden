import { mount } from '@vue/test-utils';
import { afterEach, describe, expect, it, vi } from 'vitest';

import PortsPanel from '@/features/devices/panels/PortsPanel.vue';

/**
 * 端口表视图（M5T5，PRODUCT_DESIGN §5.4-5.5 / UI_SPEC §5）：
 * - 行来自 /components（服务端分页 + kind/status 过滤）；
 * - 每行最新指标 chips 来自 /metrics/latest 按组件分组（一次取全后按组件
 *   id 关联；缺失行如实显示“尚无观测”，不伪造值）；
 * - 名称/状态列固定（横向滚动时不移动），bps 速率带单位 bit/s；
 * - unsupported/not_configured 能力行与“暂无数据”区分显示。
 */
function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

async function flushAll(): Promise<void> {
  for (let i = 0; i < 4; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

function componentRow(id: string, nativeId: string) {
  return {
    id,
    kind: 'interface',
    native_id: nativeId,
    name: nativeId,
    status: 'unknown',
    properties: {},
    first_seen_at: '2026-09-04T00:00:00Z',
    last_seen_at: '2026-09-04T08:00:00Z',
  };
}

function metricItem(key: string, value: string | number | null, unit: string | null) {
  return {
    metric_key: key,
    value,
    unit,
    quality: 'good',
    observed_at: '2026-09-04T08:00:00Z',
    source: 'poll',
    freshness: 'fresh',
  };
}

function group(component: object | null, metrics: unknown[]) {
  return { component, metrics };
}

const SUPPORTED = (
  key: string,
): {
  capability_key: string;
  requirement_id: string;
  requirement_title: string;
  support_state: string;
  reason_code: string | null;
  detail: string | null;
  discovery_method: string;
  adapter_version: string;
  last_checked_at: string;
} => ({
  capability_key: key,
  requirement_id: 'CORE-MON-02',
  requirement_title: '端口状态、流量、CRC 与丢包',
  support_state: 'supported',
  reason_code: null,
  detail: null,
  discovery_method: 'switch.huawei_vrp_core',
  adapter_version: 'simulator-verified',
  last_checked_at: '2026-09-04T08:00:00Z',
});

const capabilities = [
  SUPPORTED('interface.admin_status'),
  SUPPORTED('interface.oper_status'),
  SUPPORTED('interface.in_bps'),
  SUPPORTED('interface.out_bps'),
  SUPPORTED('interface.crc_errors'),
  SUPPORTED('interface.drops'),
  {
    ...SUPPORTED('interface.errors'),
    support_state: 'unsupported',
    reason_code: 'device_source_missing',
    detail: '设备未应答错误计数表（无该表/无数据行）',
  },
];

const PORT_1 = componentRow('c-1', 'GigabitEthernet0/0/1');
const PORT_2 = componentRow('c-2', 'GigabitEthernet0/0/2');

const LATEST_PAGE = {
  device_id: 'd-1',
  items: [
    group(
      { id: 'c-1', kind: 'interface', native_id: 'GigabitEthernet0/0/1', name: 'GigabitEthernet0/0/1' },
      [
        metricItem('interface.admin_status', 'up', null),
        metricItem('interface.oper_status', 'up', null),
        metricItem('interface.in_bps', 125000000, 'bit/s'),
        metricItem('interface.out_bps', 250000000, 'bit/s'),
        metricItem('interface.crc_errors', 0, '1'),
        metricItem('interface.errors', 0, '1'),
        metricItem('interface.drops', 0, '1'),
      ],
    ),
    group(null, []),
  ],
  page: 1,
  page_size: 100,
  total: 2,
};

describe('端口表视图 PortsPanel（M5T5）', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  async function mountPanel(fetchMock: (url: string | URL | Request, init?: RequestInit) => Promise<Response>) {
    vi.stubGlobal('fetch', fetchMock);
    const wrapper = mount(PortsPanel, {
      props: {
        deviceId: 'd-1',
        requirementIds: ['CORE-MON-02'],
        kinds: ['interface'],
        capabilities,
      },
    });
    await flushAll();
    return wrapper;
  }

  it('渲染端口行：固定名称/状态列 + 每行最新指标 chips（含 bit/s 速率与单位）', async () => {
    const seen: Array<{ url: string; init?: RequestInit }> = [];
    const wrapper = await mountPanel(async (url, init) => {
      seen.push({ url: String(url), init });
      const target = String(url);
      if (target.includes('/components')) {
        return jsonResponse({
          device_id: 'd-1',
          items: [PORT_1],
          page: 1,
          page_size: 20,
          total: 1,
        });
      }
      if (target.includes('/metrics/latest')) {
        return jsonResponse(LATEST_PAGE);
      }
      return jsonResponse({}, 404);
    });

    expect(wrapper.find('[data-testid="port-table"]').exists()).toBe(true);
    const text = wrapper.text();
    // 行名称 + 状态（运行状态 up）+ chips
    expect(text).toContain('GigabitEthernet0/0/1');
    expect(wrapper.findAll('[data-testid="port-status"]').length).toBeGreaterThanOrEqual(1);
    expect(wrapper.get('[data-testid="port-chip-interface.in_bps"]').text()).toMatch(
      /125000000\s*bit\/s/,
    );
    expect(wrapper.get('[data-testid="port-chip-interface.out_bps"]').text()).toMatch(
      /250000000\s*bit\/s/,
    );
    expect(text).toContain('端口入向速率');
    expect(text).toContain('端口 CRC 错误');
    // UI_SPEC §5 不隐藏最近采集时间（M6T1）：状态列的观测时间与新鲜度
    // 直接可见，不依赖悬停 chips 标题
    const observedCell = wrapper.get('[data-testid="port-observed-c-1"]');
    expect(observedCell.text()).toMatch(/观测 \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/);
    expect(observedCell.text()).toContain('新鲜度 正常');
    // 服务端分页参数：components 带 kind=interface + page_size=20；
    // latest 一次取全（page_size=100）
    const componentsCall = seen.find((entry) => entry.url.includes('/components'));
    expect(componentsCall?.url).toContain('kind=interface');
    expect(componentsCall?.url).toContain('page_size=20');
    expect(componentsCall?.url).toContain('page=1');
    const latestCall = seen.find((entry) => entry.url.includes('/metrics/latest'));
    expect(latestCall?.url).toContain('page_size=100');
    // 固定列（el-table fixed）渲染：名称 + 状态两列位于固定列容器
    expect(wrapper.findAll('.el-table-fixed-column--left').length).toBeGreaterThanOrEqual(2);
  });

  it('行内观测缺失时如实显示“尚无观测”，分页翻页走服务端 page=2', async () => {
    const seen: Array<{ url: string; init?: RequestInit }> = [];
    const wrapper = await mountPanel(async (url, init) => {
      seen.push({ url: String(url), init });
      const target = String(url);
      if (target.includes('/components')) {
        if (target.includes('page=2')) {
          return jsonResponse({
            device_id: 'd-1',
            items: [PORT_2],
            page: 2,
            page_size: 20,
            total: 2,
          });
        }
        return jsonResponse({
          device_id: 'd-1',
          items: [PORT_1],
          page: 1,
          page_size: 20,
          total: 2,
        });
      }
      if (target.includes('/metrics/latest')) {
        return jsonResponse(LATEST_PAGE);
      }
      return jsonResponse({}, 404);
    });

    // 第一页只有 c-1 有观测；c-2 尚无观测时（翻页后）不伪造值
    const pagination = wrapper.findComponent({ name: 'PaginationBar' });
    expect(pagination.exists()).toBe(true);
    pagination.vm.$emit('update:page', 2);
    await flushAll();
    const second = seen.filter((entry) => entry.url.includes('/components'));
    expect(second.length).toBeGreaterThanOrEqual(2);
    expect(second[1]?.url).toContain('page=2');
    expect(wrapper.text()).toContain('尚无观测（该组件尚无一次成功观测）');
    expect(wrapper.findAll('[data-testid="port-no-observation"]').length).toBeGreaterThanOrEqual(1);
  });

  it('unsupported/not_configured 能力行显示原因（与“暂无数据”区分）', async () => {
    const wrapper = await mountPanel(async (url) => {
      const target = String(url);
      if (target.includes('/components')) {
        return jsonResponse({
          device_id: 'd-1',
          items: [PORT_1],
          page: 1,
          page_size: 20,
          total: 1,
        });
      }
      if (target.includes('/metrics/latest')) {
        return jsonResponse(LATEST_PAGE);
      }
      return jsonResponse({}, 404);
    });
    expect(wrapper.text()).toContain('interface.errors');
    expect(wrapper.text()).toContain('设备不支持');
    expect(wrapper.text()).toContain('设备未应答错误计数表');
  });

  it('状态观测已过期时状态列如实显示观测时间与“已过期”，与未知（尚无观测）区分', async () => {
    const wrapper = await mountPanel(async (url) => {
      const target = String(url);
      if (target.includes('/components')) {
        return jsonResponse({
          device_id: 'd-1',
          items: [PORT_1],
          page: 1,
          page_size: 20,
          total: 1,
        });
      }
      if (target.includes('/metrics/latest')) {
        return jsonResponse({
          device_id: 'd-1',
          items: [
            group(
              { id: 'c-1', kind: 'interface', native_id: 'GigabitEthernet0/0/1', name: 'GigabitEthernet0/0/1' },
              [
                {
                  ...metricItem('interface.oper_status', 'up', null),
                  freshness: 'expired',
                  observed_at: '2026-09-01T08:00:00Z',
                },
                {
                  ...metricItem('interface.in_bps', 1000, 'bit/s'),
                  freshness: 'expired',
                  observed_at: '2026-09-01T08:00:00Z',
                },
              ],
            ),
          ],
          page: 1,
          page_size: 100,
          total: 1,
        });
      }
      return jsonResponse({}, 404);
    });
    const observedCell = wrapper.get('[data-testid="port-observed-c-1"]');
    expect(observedCell.text()).toMatch(/观测 \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/);
    expect(observedCell.text()).toContain('新鲜度 已过期');
    // 过期仍然展示最后已知值，不伪装成"暂无数据"
    expect(wrapper.text()).not.toContain('尚无观测（该组件尚无一次成功观测）');
  });
});
