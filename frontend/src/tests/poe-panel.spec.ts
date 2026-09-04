import { mount } from '@vue/test-utils';
import { afterEach, describe, expect, it, vi } from 'vitest';

import PoePanel from '@/features/devices/panels/PoePanel.vue';

/**
 * PoE 视图（M5T5，PRODUCT_DESIGN §5.5 PoE 页签 + ACCESS-MON-03）：
 * - 设备级摘要卡片：总功耗/功率预算/总功率占比/总功率告警（只显示设备
 *   实际报告的值；缺失的百分比/告警显示“尚无观测”而不是伪造 normal）；
 * - poe_port 行表：供电状态 + 单端口功耗 chips（服务端分页）。
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

function poePortRow(id: string, nativeId: string) {
  return {
    id,
    kind: 'poe_port',
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

const PORT_1 = poePortRow('p-1', 'GigabitEthernet0/0/1');
const PORT_2 = poePortRow('p-2', 'GigabitEthernet0/0/2');

const SUMMARY_PAGE = {
  device_id: 'd-1',
  items: [
    group(null, [
      metricItem('poe.total_power_w', 80, 'W'),
      metricItem('poe.power_budget_w', 400, 'W'),
      metricItem('poe.total_power_percent', 20, '%'),
      metricItem('poe.total_power_alarm', 'normal', null),
    ]),
    group(
      { id: 'p-1', kind: 'poe_port', native_id: 'GigabitEthernet0/0/1', name: 'GigabitEthernet0/0/1' },
      [metricItem('poe.port.status', 'on', null), metricItem('poe.port.power_w', 5, 'W')],
    ),
    group(
      { id: 'p-2', kind: 'poe_port', native_id: 'GigabitEthernet0/0/2', name: 'GigabitEthernet0/0/2' },
      [metricItem('poe.port.status', 'off', null), metricItem('poe.port.power_w', 0, 'W')],
    ),
  ],
  page: 1,
  page_size: 100,
  total: 3,
};

function group(component: object | null, metrics: unknown[]) {
  return { component, metrics };
}

const capability = (
  key: string,
  extra: { support_state: string; reason_code: string | null; detail: string | null },
) => ({
  capability_key: key,
  requirement_id: 'ACCESS-MON-03',
  requirement_title: 'PoE 状态与功耗',
  support_state: extra.support_state,
  reason_code: extra.reason_code,
  detail: extra.detail,
  discovery_method: 'switch.huawei_vrp_access',
  adapter_version: 'simulator-verified',
  last_checked_at: '2026-09-04T08:00:00Z',
});

const capabilities = [
  capability('poe.port.status', { support_state: 'supported', reason_code: null, detail: null }),
  capability('poe.port.power_w', { support_state: 'supported', reason_code: null, detail: null }),
  capability('poe.total_power_w', { support_state: 'supported', reason_code: null, detail: null }),
  capability('poe.power_budget_w', { support_state: 'supported', reason_code: null, detail: null }),
  capability('poe.total_power_percent', {
    support_state: 'supported',
    reason_code: null,
    detail: null,
  }),
  capability('poe.total_power_alarm', {
    support_state: 'supported',
    reason_code: null,
    detail: null,
  }),
];

describe('PoE 视图 PoePanel（M5T5）', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  async function mountPanel(
    fetchMock: (url: string | URL | Request, init?: RequestInit) => Promise<Response>,
  ) {
    vi.stubGlobal('fetch', fetchMock);
    const wrapper = mount(PoePanel, {
      props: {
        deviceId: 'd-1',
        requirementIds: ['ACCESS-MON-03'],
        kinds: ['poe_port'],
        capabilities,
      },
    });
    await flushAll();
    return wrapper;
  }

  it('渲染总功耗/预算/占比/告警摘要与逐端口供电行', async () => {
    const seen: string[] = [];
    const wrapper = await mountPanel(async (url) => {
      const target = String(url);
      seen.push(target);
      if (target.includes('/components')) {
        return jsonResponse({
          device_id: 'd-1',
          items: [PORT_1, PORT_2],
          page: 1,
          page_size: 20,
          total: 2,
        });
      }
      if (target.includes('/metrics/latest')) {
        return jsonResponse(SUMMARY_PAGE);
      }
      return jsonResponse({}, 404);
    });

    const text = wrapper.text();
    // 摘要：80 W / 400 W / 20 % / 告警 normal -> 正常
    expect(text).toContain('设备 PoE 总功耗');
    expect(wrapper.get('[data-testid="poe-summary-poe.total_power_w"]').text()).toMatch(/80\s*W/);
    expect(wrapper.get('[data-testid="poe-summary-poe.power_budget_w"]').text()).toMatch(
      /400\s*W/,
    );
    expect(wrapper.get('[data-testid="poe-summary-poe.total_power_percent"]').text()).toMatch(
      /20\s*%/,
    );
    expect(wrapper.get('[data-testid="poe-summary-poe.total_power_alarm"]').text()).toContain(
      '正常',
    );
    // 行表：供电状态（on/off -> 开启/关闭）+ 单端口功耗
    expect(text).toContain('PoE 端口供电');
    expect(text).toContain('GigabitEthernet0/0/1');
    expect(text).toContain('开启');
    expect(text).toContain('关闭');
    const powerChips = wrapper.findAll('[data-testid="port-chip-poe.port.power_w"]');
    expect(powerChips.length).toBeGreaterThanOrEqual(2);
    expect(powerChips[0]?.text()).toMatch(/5\s*W/);
    // components 调用固定 kind=poe_port（服务端过滤）
    expect(seen.find((url) => url.includes('/components'))).toContain('kind=poe_port');
  });

  it('占比与告警缺失时如实显示“尚无观测”（不伪造百分比/normal）', async () => {
    const page = {
      device_id: 'd-1',
      items: [
        group(null, [metricItem('poe.total_power_w', 80, 'W')]),
        group(
          {
            id: 'p-1',
            kind: 'poe_port',
            native_id: 'GigabitEthernet0/0/1',
            name: 'GigabitEthernet0/0/1',
          },
          [metricItem('poe.port.status', 'on', null)],
        ),
      ],
      page: 1,
      page_size: 100,
      total: 2,
    };
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
        return jsonResponse(page);
      }
      return jsonResponse({}, 404);
    });
    expect(wrapper.get('[data-testid="poe-summary-poe.total_power_percent"]').text()).toContain(
      '尚无观测',
    );
    expect(wrapper.get('[data-testid="poe-summary-poe.total_power_alarm"]').text()).toContain(
      '尚无观测',
    );
    expect(wrapper.text()).not.toContain('正常');
  });

  it('not_configured 能力行显示原因（设备未提供预算分母等）', async () => {
    const caps = capabilities.map((row) =>
      row.capability_key === 'poe.total_power_percent'
        ? { ...row, support_state: 'not_configured', reason_code: 'device_source_missing', detail: 'no_budget_denominator：设备未提供功率预算（缺失分母，不伪造百分比）' }
        : row,
    );
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: RequestInfo | URL) => {
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
          return jsonResponse(SUMMARY_PAGE);
        }
        return jsonResponse({}, 404);
      }),
    );
    const wrapper = mount(PoePanel, {
      props: {
        deviceId: 'd-1',
        requirementIds: ['ACCESS-MON-03'],
        kinds: ['poe_port'],
        capabilities: caps,
      },
    });
    await flushAll();
    expect(wrapper.text()).toContain('poe.total_power_percent');
    expect(wrapper.text()).toContain('未配置');
    expect(wrapper.text()).toContain('no_budget_denominator');
  });
});
