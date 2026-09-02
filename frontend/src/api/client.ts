import { ERROR_CODES, type ErrorCode } from '@/api/generated/contracts';
import type { components } from '@/api/generated/openapi';

type ErrorBody = components['schemas']['ErrorBody'];

const DEFAULT_TIMEOUT_MS = 15_000;

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

let csrfTokenProvider: (() => string | null) | null = null;

/**
 * M1（PLT-01）登录后注入 CSRF 票据提供者。
 * 票据只在内存中持有，永不写入 localStorage（SECURITY.md §2）。
 */
export function setCsrfTokenProvider(provider: (() => string | null) | null): void {
  csrfTokenProvider = provider;
}

/**
 * 会话失效处理槽：401 session_expired / csrf_failed 时由调用方（router 层）
 * 注入清理与重定向逻辑，避免 client 与 store/router 形成循环依赖。
 */
let sessionExpiredHandler: (() => void) | null = null;

export function setSessionExpiredHandler(handler: (() => void) | null): void {
  sessionExpiredHandler = handler;
}

/** 会话或 CSRF 失效：这类错误只能通过重新登录恢复。 */
export function isSessionRecoverableError(error: ApiError): boolean {
  return (
    error.code === 'session_expired' ||
    error.code === 'unauthenticated' ||
    error.code === 'csrf_failed'
  );
}

export function apiBaseUrl(): string {
  return import.meta.env.VITE_API_BASE ?? '/api/v1';
}

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  body?: unknown;
  headers?: Record<string, string>;
  timeoutMs?: number;
}

/** 客户端只依赖 code，不解析 message（contracts/error-codes.json）。 */
export class ApiError extends Error {
  readonly code: ErrorCode;
  readonly details: Record<string, unknown>;
  readonly request_id: string;
  readonly httpStatus: number;

  constructor(
    httpStatus: number,
    body: {
      code: ErrorCode;
      message: string;
      details: Record<string, unknown>;
      request_id: string;
    },
  ) {
    super(body.message);
    this.name = 'ApiError';
    this.code = body.code;
    this.details = body.details;
    this.request_id = body.request_id;
    this.httpStatus = httpStatus;
  }
}

function isErrorCode(value: string): value is ErrorCode {
  return (ERROR_CODES as readonly string[]).includes(value);
}

/** 判定错误是否来自服务端错误信封（网络失败等 TypeError 不是 ApiError）。 */
export function isApiError(error: unknown): error is ApiError {
  return error instanceof ApiError;
}

async function parseError(response: Response): Promise<ApiError> {
  const requestIdFromHeader = response.headers.get('x-request-id') ?? '';
  let envelope: { error?: Partial<ErrorBody> } | null = null;
  try {
    envelope = (await response.json()) as { error?: Partial<ErrorBody> } | null;
  } catch {
    // 非 JSON 响应按内部错误处理，只保留可安全展示的字段
  }
  const error = envelope?.error;
  if (error && typeof error.code === 'string' && typeof error.message === 'string') {
    return new ApiError(response.status, {
      code: isErrorCode(error.code) ? error.code : 'internal_error',
      message: error.message,
      details: typeof error.details === 'object' && error.details !== null ? error.details : {},
      request_id:
        typeof error.request_id === 'string' && error.request_id !== ''
          ? error.request_id
          : requestIdFromHeader,
    });
  }
  return new ApiError(response.status, {
    code: 'internal_error',
    message: '服务器内部错误',
    details: {},
    request_id: requestIdFromHeader,
  });
}

/**
 * fetch 封装：统一错误信封、CSRF 头槽位与超时。
 * 不解析、不返回信封之外的任何字段，避免凭据等敏感内容进入客户端错误对象。
 */
export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = {
    Accept: 'application/json',
    ...options.headers,
  };
  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }
  const csrfToken = csrfTokenProvider?.();
  if (csrfToken && options.method !== undefined && MUTATING_METHODS.has(options.method)) {
    headers['X-CSRF-Token'] = csrfToken;
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  try {
    const response = await fetch(apiBaseUrl() + path, {
      method: options.method ?? 'GET',
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: controller.signal,
    });
    if (!response.ok) {
      const error = await parseError(response);
      if (isSessionRecoverableError(error)) {
        sessionExpiredHandler?.();
      }
      throw error;
    }
    if (response.status === 204) {
      return undefined as T;
    }
    return (await response.json()) as T;
  } finally {
    clearTimeout(timer);
  }
}
