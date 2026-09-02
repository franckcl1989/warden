/**
 * 轻量查询缓存（M2T7）：页面把"数据已变化时需要重取的闭包"注册进来，
 * SSE 实时层按实体种类失效对应条目后由注册方自动重取。
 *
 * 约束（M2T7 决策）：不引入重型缓存库；条目只保存"重取函数 + 元数据"，
 * 不缓存响应数据本身（数据仍由各页面 ref 持有）。失效语义：
 * - invalidate(kind) 使所有该种类条目重取（如 alerts）；
 * - invalidate(kind, id) 命中 kind 且 id 一致的条目（如当前正在查看的任务）；
 * - invalidateAll() 对应 SSE `reset` 事件的全量重取信号。
 */

export type CacheKind =
  | 'overview'
  | 'devices'
  | 'device-detail'
  | 'alerts'
  | 'operations'
  | 'operation-detail'
  | 'files'
  | 'system';

export interface CacheEntry {
  kind: CacheKind;
  /** 可选实体 ID：operation-detail 用任务 ID，device-detail 用设备 ID。 */
  id?: string;
  refetch: () => void | Promise<void>;
}

interface EntryRecord {
  kind: CacheKind;
  id?: string;
  refetch: () => void;
}

const entries = new Set<EntryRecord>();

function asyncRunner(refetch: () => void | Promise<void>): () => void {
  let running = false;
  return () => {
    if (running) {
      return;
    }
    running = true;
    Promise.resolve()
      .then(refetch)
      .catch(() => undefined)
      .finally(() => {
        running = false;
      });
  };
}

/** 注册一个失效回调；返回取消注册函数。重复注册同 kind+id 会先取消旧条目。 */
export function registerCacheEntry(entry: CacheEntry): () => void {
  for (const existing of entries) {
    if (existing.kind === entry.kind && existing.id === entry.id) {
      entries.delete(existing);
    }
  }
  const record: EntryRecord = {
    kind: entry.kind,
    id: entry.id,
    refetch: asyncRunner(entry.refetch),
  };
  entries.add(record);
  return () => {
    entries.delete(record);
  };
}

function runEntry(entry: EntryRecord): void {
  try {
    entry.refetch();
  } catch {
    // 重取失败由各页面自己的状态处理，实时层不吞错误详情
  }
}

/** 按实体种类失效（不携带具体 ID 的事件，如 alert 列表变化）。 */
export function invalidateCache(kind: CacheKind): void {
  for (const entry of entries) {
    if (entry.kind === kind) {
      runEntry(entry);
    }
  }
}

/** 按实体种类 + 实体 ID 失效（如任务详情）。 */
export function invalidateCacheById(kind: CacheKind, id: string): void {
  for (const entry of entries) {
    if (entry.kind === kind && (entry.id === undefined || entry.id === id)) {
      runEntry(entry);
    }
  }
}

/** 全量重取：SSE `reset` 事件（窗口外游标失效）时调用。 */
export function invalidateAllCache(): void {
  for (const entry of entries) {
    runEntry(entry);
  }
}
