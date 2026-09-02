import { mount } from '@vue/test-utils';
import { afterEach, describe, expect, it, vi } from 'vitest';

import MetricChart from '@/components/MetricChart.vue';

/**
 * MetricChart 测试（UI_SPEC §7.3）：
 * - 时间范围选择 1h/6h/24h/7d/30d/180d（默认 24 小时）；
 * - 分辨率显示服务端返回的实际分辨率（raw → 原始点）；
 * - 最多 8 条序列（多组件只发起 8 个 series 请求并提示上限）；
 * - device 作用域指标（如 system.cpu_percent）只请求单条无 component 序列；
 * - 空系列显示"没有可绘制的数据点"（诚实空态，非错误）；
 * - 文本摘要（当前/最高/最低）供无障碍。
 */
function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function seriesResponse(extra: Record<string, unknown> = {}) {
  return {
    device_id: 'd-1',
    metric_key: 'temperature.cpu',
    series: 'gauge',
    value_type: 'number',
    unit: 'Cel',
    component_id: 'c-1',
    resolution: 'raw',
    points: [
      { timestamp: '2026-09-01T08:00:00Z', value: 41.5, quality: 'good' },
      { timestamp: '2026-09-01T08:01:00Z', value: null, quality: 'partial' },
      { timestamp: '2026-09-01T08:02:00Z', value: 42.1, quality: 'good' },
    ],
    ...extra,
  };
}

function components(count: number) {
  return Array.from({ length: count }, (_, index) => ({
    id: `c-${index + 1}`,
    kind: 'processor',
    native_id: `cpu-${index + 1}`,
    name: `CPU ${index + 1}`,
  }));
}

async function flushAll(): Promise<void> {
  for (let i = 0; i < 4; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

describe('MetricChart（UI_SPEC §7.3）', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('显示实际分辨率与文本摘要，空缺口点不参与当前/最高/最低统计', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => jsonResponse(seriesResponse())),
    );
    const wrapper = mount(MetricChart, {
      props: {
        deviceId: 'd-1',
        metricKey: 'temperature.cpu',
        candidateComponents: components(1),
      },
    });
    await flushAll();
    expect(wrapper.text()).toContain('分辨率：原始点');
    expect(wrapper.text()).toContain('单位：°C');
    const summary = wrapper.get('[data-testid="chart-summary"]');
    expect(summary.text()).toContain('cpu-1');
    expect(summary.text()).toContain('当前 42.1');
    expect(summary.text()).toContain('最高 42.1');
    expect(summary.text()).toContain('最低 41.5');
    expect(summary.text()).not.toContain('—'); // 空缺口不参与最值统计
  });

  it('时间范围默认 24 小时且提供六个范围选项', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(seriesResponse()));
    vi.stubGlobal('fetch', fetchMock);
    const wrapper = mount(MetricChart, {
      props: {
        deviceId: 'd-1',
        metricKey: 'temperature.cpu',
        candidateComponents: components(1),
      },
    });
    await flushAll();
    const labels = wrapper
      .findAll('[data-testid="chart-range"] .el-radio-button')
      .map((button) => button.text())
      .filter((text) => text.length > 0);
    expect(labels).toEqual(['1 小时', '6 小时', '24 小时', '7 天', '30 天', '180 天']);
    const firstCallArgs = fetchMock.mock.calls[0] as unknown as [string] | undefined;
    expect(String(firstCallArgs?.[0] ?? '')).toContain('from=');
  });

  it('超过 8 个候选组件只请求前 8 条并提示上限', async () => {
    const fetchMock = vi.fn(async (url: string) => {
      const u = String(url);
      if (u.includes('/metrics/series')) {
        const componentId = new URLSearchParams(u.split('?')[1] ?? '').get('component_id');
        return jsonResponse(seriesResponse({ component_id: componentId }));
      }
      return jsonResponse({});
    });
    vi.stubGlobal('fetch', fetchMock);
    const wrapper = mount(MetricChart, {
      props: {
        deviceId: 'd-1',
        metricKey: 'temperature.cpu',
        candidateComponents: components(12),
      },
    });
    await flushAll();
    expect(wrapper.text()).toContain('最多选择 8 条序列');
    const seriesCalls = fetchMock.mock.calls.filter((call) =>
      String(call[0]).includes('/metrics/series'),
    );
    expect(seriesCalls).toHaveLength(8);
  });

  it('device 作用域指标只请求一条不带 component_id 的序列', async () => {
    const fetchMock = vi.fn(async (url: string) => {
      const u = String(url);
      if (u.includes('/metrics/series')) {
        return jsonResponse(
          seriesResponse({
            metric_key: 'system.cpu_percent',
            series: 'gauge',
            value_type: 'number',
            unit: '%',
            component_id: null,
          }),
        );
      }
      return jsonResponse({});
    });
    vi.stubGlobal('fetch', fetchMock);
    const wrapper = mount(MetricChart, {
      props: { deviceId: 'd-1', metricKey: 'system.cpu_percent' },
    });
    await flushAll();
    const seriesCalls = fetchMock.mock.calls.filter((call) =>
      String(call[0]).includes('/metrics/series'),
    );
    expect(seriesCalls).toHaveLength(1);
    const url = new URLSearchParams(String(seriesCalls[0]?.[0]).split('?')[1] ?? '');
    expect(url.get('component_id')).toBeNull();
    expect(wrapper.text()).toContain('单位：%');
  });

  it('无数据点时展示诚实空态并保持分辨率信息', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => jsonResponse(seriesResponse({ points: [] }))),
    );
    const wrapper = mount(MetricChart, {
      props: {
        deviceId: 'd-1',
        metricKey: 'temperature.cpu',
        candidateComponents: components(2),
      },
    });
    await flushAll();
    expect(wrapper.get('[data-testid="chart-empty"]').text()).toContain(
      '该时间范围内没有可绘制的数据点',
    );
  });

  it('较早的慢响应不会覆盖较新的请求结果（请求序列化）', async () => {
    const resolvers: ((response: Response) => void)[] = [];
    const fetchMock = vi.fn(
      () =>
        new Promise<Response>((resolve) => {
          resolvers.push(resolve);
        }),
    );
    vi.stubGlobal('fetch', fetchMock);
    const wrapper = mount(MetricChart, {
      props: {
        deviceId: 'd-1',
        metricKey: 'temperature.cpu',
        candidateComponents: components(1),
      },
    });
    await flushAll();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const range = wrapper
      .get('[data-testid="chart-range"]')
      .findComponent({ name: 'ElRadioGroup' });
    await range.vm.$emit('update:modelValue', 6);
    await flushAll();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    // 新请求（6 小时范围）先返回
    resolvers[1]!(
      jsonResponse(
        seriesResponse({
          points: [{ timestamp: '2026-09-01T08:00:00Z', value: 58.9, quality: 'good' }],
        }),
      ),
    );
    await flushAll();
    // 旧请求（24 小时范围）随后才返回：不得覆盖新结果
    resolvers[0]!(
      jsonResponse(
        seriesResponse({
          points: [{ timestamp: '2026-09-01T08:00:00Z', value: 41.5, quality: 'good' }],
        }),
      ),
    );
    await flushAll();
    const summary = wrapper.get('[data-testid="chart-summary"]');
    expect(summary.text()).toContain('当前 58.9');
    expect(summary.text()).not.toContain('当前 41.5');
  });

  it('状态/枚举系列文本摘要展示状态标签，不做数值统计', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse(
          seriesResponse({
            metric_key: 'fan.status',
            series: 'state',
            value_type: 'enum',
            unit: null,
            points: [
              { timestamp: '2026-09-01T08:00:00Z', value: 'ok', quality: 'good' },
              { timestamp: '2026-09-01T08:01:00Z', value: null, quality: 'partial' },
              { timestamp: '2026-09-01T08:02:00Z', value: 'warning', quality: 'good' },
            ],
          }),
        ),
      ),
    );
    const wrapper = mount(MetricChart, {
      props: {
        deviceId: 'd-1',
        metricKey: 'fan.status',
        candidateComponents: components(1),
      },
    });
    await flushAll();
    const summary = wrapper.get('[data-testid="chart-summary"]');
    expect(summary.text()).toContain('当前 警告');
    expect(summary.text()).toContain('观测状态：正常、警告');
    expect(summary.text()).not.toContain('无数值点');
    expect(summary.text()).not.toContain('最高');
  });
});
