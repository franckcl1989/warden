/** 时间/数值/单位展示工具：UTC ISO 字符串 → 本地可读文本。 */

export function formatDateTime(value: string | null | undefined): string {
  if (value === null || value === undefined) {
    return '—';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return '—';
  }
  const pad = (n: number): string => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(
    date.getHours(),
  )}:${pad(date.getMinutes())}`;
}

/** 日期 + 秒级时间（任务时间线等需要秒的场景）。 */
export function formatDateTimeSeconds(value: string | null | undefined): string {
  if (value === null || value === undefined) {
    return '—';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return '—';
  }
  const pad = (n: number): string => String(n).padStart(2, '0');
  return `${formatDateTime(value)}:${pad(date.getSeconds())}`;
}

/** 仅时间（图表轴等）。 */
export function formatTime(value: string | null | undefined): string {
  if (value === null || value === undefined) {
    return '—';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return '—';
  }
  const pad = (n: number): string => String(n).padStart(2, '0');
  return `${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/** 秒 → 人类可读时长，例如 900 → 15 分钟、7200 → 2 小时。 */
export function formatDuration(totalSeconds: number | null | undefined): string {
  if (totalSeconds === null || totalSeconds === undefined || !Number.isFinite(totalSeconds)) {
    return '—';
  }
  if (totalSeconds < 60) {
    return `${Math.round(totalSeconds)} 秒`;
  }
  const minutes = Math.round(totalSeconds / 60);
  if (minutes < 60) {
    return `${minutes} 分钟`;
  }
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  return rest > 0 ? `${hours} 小时 ${rest} 分钟` : `${hours} 小时`;
}

/** 字节 → 人类可读大小（文件列表）。 */
export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) {
    return '—';
  }
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let value = bytes;
  let unit = 'B';
  for (const candidate of units) {
    if (value < 1024) {
      break;
    }
    value /= 1024;
    unit = candidate;
  }
  return `${value >= 100 ? value.toFixed(0) : value.toFixed(1)} ${unit}`;
}

/** contracts/metrics.json 单位 → 界面单位；无定义的单位原样展示。 */
const UNIT_DISPLAY: Record<string, string> = {
  Cel: '°C',
};

export function unitLabel(unit: string | null | undefined): string {
  if (unit === null || unit === undefined || unit === '') {
    return '';
  }
  return UNIT_DISPLAY[unit] ?? unit;
}

/** 数值序列 y 轴单位；图表量级友好格式化。 */
export function formatAxisNumber(value: number): string {
  if (value === 0) {
    return '0';
  }
  const abs = Math.abs(value);
  if (abs >= 1_000_000_000) {
    return `${(value / 1_000_000_000).toFixed(1)}G`;
  }
  if (abs >= 1_000_000) {
    return `${(value / 1_000_000).toFixed(1)}M`;
  }
  if (abs >= 1_000) {
    return `${(value / 1_000).toFixed(1)}k`;
  }
  if (abs < 0.01 && abs > 0) {
    return value.toExponential(1);
  }
  return Number.isInteger(value) ? String(value) : value.toFixed(2);
}

/** 指标当前值 → 可读字符串（枚举/布尔走英文原值，数值保留尾数）。 */
export function formatMetricValue(value: number | string | boolean | null | undefined): string {
  if (value === null || value === undefined) {
    return '—';
  }
  if (typeof value === 'boolean') {
    return value ? '是' : '否';
  }
  if (typeof value === 'string') {
    return value;
  }
  return Number.isInteger(value) ? String(value) : String(Number(value.toFixed(4)));
}
