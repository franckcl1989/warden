import { afterEach, describe, expect, it, vi } from 'vitest';

import { ApiError, request, setCsrfTokenProvider } from '@/api/client';

function jsonResponse(body: unknown, status: number, headers?: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

async function expectApiError(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (error) {
    return error as ApiError;
  }
  throw new Error('expected ApiError');
}

describe('api client 错误信封解析', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    setCsrfTokenProvider(null);
  });

  it('从错误信封中暴露 code/details/request_id', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse(
          {
            error: {
              code: 'permission_denied',
              message: '无权限',
              details: { permission: 'devices:create' },
              request_id: 'req-001',
            },
          },
          403,
        ),
      ),
    );
    const err = await expectApiError(request('/devices'));
    expect(err).toBeInstanceOf(ApiError);
    expect(err.code).toBe('permission_denied');
    expect(err.message).toBe('无权限');
    expect(err.details).toEqual({ permission: 'devices:create' });
    expect(err.request_id).toBe('req-001');
    expect(err.httpStatus).toBe(403);
  });

  it('不暴露信封之外的字段（凭据等敏感内容不进客户端错误对象）', async () => {
    const secret = 'password-is-42';
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse(
          {
            error: {
              code: 'unauthenticated',
              message: '未认证',
              details: {},
              request_id: 'req-002',
            },
            credentials: { password: secret },
          },
          401,
        ),
      ),
    );
    const err = await expectApiError(request('/auth/me'));
    expect(err).toHaveProperty('code', 'unauthenticated');
    expect(err).not.toHaveProperty('credentials');
    expect(JSON.stringify(err)).not.toContain(secret);
  });

  it('未登记错误码在边界转换为 internal_error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse(
          { error: { code: 'made_up_code', message: 'x', details: {}, request_id: 'req-003' } },
          500,
        ),
      ),
    );
    const err = await expectApiError(request('/anything'));
    expect(err.code).toBe('internal_error');
  });

  it('非 JSON 错误响应也返回 internal_error 并带 x-request-id', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response('gateway down', { status: 502, headers: { 'x-request-id': 'req-004' } }),
      ),
    );
    const err = await expectApiError(request('/health/ready'));
    expect(err.code).toBe('internal_error');
    expect(err.request_id).toBe('req-004');
  });

  it('成功响应返回解析后的数据，并携带 CSRF 头槽位', async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ status: 'ok' }, 200));
    vi.stubGlobal('fetch', fetchMock);
    setCsrfTokenProvider(() => 'csrf-token-1');
    const data = await request<{ status: string }>('/health/live');
    expect(data).toEqual({ status: 'ok' });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('/api/v1/health/live');
    expect(init.headers).toMatchObject({
      Accept: 'application/json',
      'X-CSRF-Token': 'csrf-token-1',
    });
  });
});
