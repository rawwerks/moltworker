import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  PrivilegedSecretHandler,
  type SecretResolver,
  type ResolvedSecret,
  type SecretProxyRequest,
} from './handler';
import { SecretCache } from './cache';

// Mock global fetch
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

function createMockResolver(secrets: Record<string, ResolvedSecret> = {}): SecretResolver {
  return {
    resolve: vi.fn(async (_orgId: string, name: string) => secrets[name] ?? null),
  };
}

function makeSecret(plaintext: string, overrides: Partial<ResolvedSecret> = {}): ResolvedSecret {
  return {
    encrypted_value: 'base64ciphertext',
    thumbprint: 'sha256:abc',
    injection_mode: 'bearer',
    plaintext,
    ...overrides,
  };
}

function makeRequest(overrides: Partial<SecretProxyRequest> = {}): SecretProxyRequest {
  return {
    name: 'GITHUB_TOKEN',
    injection_mode: 'bearer',
    url: 'https://api.github.com/user',
    ...overrides,
  };
}

describe('PrivilegedSecretHandler', () => {
  let handler: PrivilegedSecretHandler;
  let resolver: SecretResolver;

  beforeEach(() => {
    vi.clearAllMocks();
    mockFetch.mockResolvedValue(
      new Response('{"login":"test"}', {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    );
  });

  describe('validation', () => {
    beforeEach(() => {
      resolver = createMockResolver();
      handler = new PrivilegedSecretHandler(resolver);
    });

    it('rejects missing secret name', async () => {
      const result = await handler.proxy('org_1', makeRequest({ name: '' }));
      expect(result.status).toBe(400);
      expect(JSON.parse(result.body).error).toContain('name');
    });

    it('rejects missing injection_mode', async () => {
      const result = await handler.proxy('org_1', makeRequest({ injection_mode: '' }));
      expect(result.status).toBe(400);
      expect(JSON.parse(result.body).error).toContain('injection_mode');
    });

    it('rejects missing URL', async () => {
      const result = await handler.proxy('org_1', makeRequest({ url: '' }));
      expect(result.status).toBe(400);
      expect(JSON.parse(result.body).error).toContain('URL');
    });

    it('rejects invalid URL', async () => {
      const result = await handler.proxy('org_1', makeRequest({ url: 'not-a-url' }));
      expect(result.status).toBe(400);
      expect(JSON.parse(result.body).error).toContain('Invalid target URL');
    });

    it('rejects invalid injection mode', async () => {
      const result = await handler.proxy('org_1', makeRequest({ injection_mode: 'raw' }));
      expect(result.status).toBe(400);
      expect(JSON.parse(result.body).error).toContain('injection_mode');
    });

    it('accepts bearer mode', async () => {
      resolver = createMockResolver({ GITHUB_TOKEN: makeSecret('ghp_test') });
      handler = new PrivilegedSecretHandler(resolver);
      const result = await handler.proxy('org_1', makeRequest({ injection_mode: 'bearer' }));
      expect(result.status).toBe(200);
    });

    it('accepts basic mode', async () => {
      resolver = createMockResolver({ GITHUB_TOKEN: makeSecret('user:pass') });
      handler = new PrivilegedSecretHandler(resolver);
      const result = await handler.proxy('org_1', makeRequest({ injection_mode: 'basic' }));
      expect(result.status).toBe(200);
    });

    it('accepts header:<name> mode', async () => {
      resolver = createMockResolver({ GITHUB_TOKEN: makeSecret('key123') });
      handler = new PrivilegedSecretHandler(resolver);
      const result = await handler.proxy(
        'org_1',
        makeRequest({ injection_mode: 'header:X-Api-Key' }),
      );
      expect(result.status).toBe(200);
    });

    it('accepts query:<param> mode', async () => {
      resolver = createMockResolver({ GITHUB_TOKEN: makeSecret('key123') });
      handler = new PrivilegedSecretHandler(resolver);
      const result = await handler.proxy(
        'org_1',
        makeRequest({ injection_mode: 'query:api_key' }),
      );
      expect(result.status).toBe(200);
    });

    it('accepts body:<field> mode', async () => {
      resolver = createMockResolver({ GITHUB_TOKEN: makeSecret('key123') });
      handler = new PrivilegedSecretHandler(resolver);
      const result = await handler.proxy(
        'org_1',
        makeRequest({ injection_mode: 'body:token', method: 'POST' }),
      );
      expect(result.status).toBe(200);
    });
  });

  describe('secret resolution', () => {
    it('returns 404 when secret not found', async () => {
      resolver = createMockResolver({});
      handler = new PrivilegedSecretHandler(resolver);
      const result = await handler.proxy('org_1', makeRequest());
      expect(result.status).toBe(404);
      expect(JSON.parse(result.body).error).toContain('not found');
    });

    it('calls resolver with correct organism ID and name', async () => {
      resolver = createMockResolver({ GITHUB_TOKEN: makeSecret('ghp_test') });
      handler = new PrivilegedSecretHandler(resolver);
      await handler.proxy('org_42', makeRequest({ name: 'GITHUB_TOKEN' }));
      expect(resolver.resolve).toHaveBeenCalledWith('org_42', 'GITHUB_TOKEN');
    });
  });

  describe('injection modes', () => {
    it('injects bearer token in Authorization header', async () => {
      resolver = createMockResolver({ TOKEN: makeSecret('ghp_secret123') });
      handler = new PrivilegedSecretHandler(resolver);
      await handler.proxy('org_1', makeRequest({ name: 'TOKEN', injection_mode: 'bearer' }));

      const [, init] = mockFetch.mock.calls[0];
      const headers = new Headers(init.headers);
      expect(headers.get('Authorization')).toBe('Bearer ghp_secret123');
    });

    it('injects basic auth in Authorization header', async () => {
      resolver = createMockResolver({ TOKEN: makeSecret('user:pass') });
      handler = new PrivilegedSecretHandler(resolver);
      await handler.proxy('org_1', makeRequest({ name: 'TOKEN', injection_mode: 'basic' }));

      const [, init] = mockFetch.mock.calls[0];
      const headers = new Headers(init.headers);
      expect(headers.get('Authorization')).toBe(`Basic ${btoa('user:pass')}`);
    });

    it('injects custom header', async () => {
      resolver = createMockResolver({ API_KEY: makeSecret('key123') });
      handler = new PrivilegedSecretHandler(resolver);
      await handler.proxy(
        'org_1',
        makeRequest({ name: 'API_KEY', injection_mode: 'header:X-Api-Key' }),
      );

      const [, init] = mockFetch.mock.calls[0];
      const headers = new Headers(init.headers);
      expect(headers.get('X-Api-Key')).toBe('key123');
    });

    it('injects query parameter', async () => {
      resolver = createMockResolver({ API_KEY: makeSecret('key123') });
      handler = new PrivilegedSecretHandler(resolver);
      await handler.proxy(
        'org_1',
        makeRequest({
          name: 'API_KEY',
          injection_mode: 'query:api_key',
          url: 'https://api.example.com/data',
        }),
      );

      const [url] = mockFetch.mock.calls[0];
      expect(url).toContain('api_key=key123');
    });

    it('injects body field', async () => {
      resolver = createMockResolver({ API_KEY: makeSecret('key123') });
      handler = new PrivilegedSecretHandler(resolver);
      await handler.proxy(
        'org_1',
        makeRequest({
          name: 'API_KEY',
          injection_mode: 'body:token',
          method: 'POST',
          body: '{"other":"data"}',
        }),
      );

      const [, init] = mockFetch.mock.calls[0];
      const body = JSON.parse(init.body);
      expect(body.token).toBe('key123');
      expect(body.other).toBe('data');
    });

    it('sets Content-Type for body injection when not present', async () => {
      resolver = createMockResolver({ API_KEY: makeSecret('key123') });
      handler = new PrivilegedSecretHandler(resolver);
      await handler.proxy(
        'org_1',
        makeRequest({
          name: 'API_KEY',
          injection_mode: 'body:token',
          method: 'POST',
        }),
      );

      const [, init] = mockFetch.mock.calls[0];
      const headers = new Headers(init.headers);
      expect(headers.get('Content-Type')).toBe('application/json');
    });
  });

  describe('outbound request', () => {
    beforeEach(() => {
      resolver = createMockResolver({ TOKEN: makeSecret('secret') });
      handler = new PrivilegedSecretHandler(resolver);
    });

    it('forwards custom headers', async () => {
      await handler.proxy(
        'org_1',
        makeRequest({
          name: 'TOKEN',
          headers: { Accept: 'application/json', 'X-Custom': 'value' },
        }),
      );

      const [, init] = mockFetch.mock.calls[0];
      const headers = new Headers(init.headers);
      expect(headers.get('Accept')).toBe('application/json');
      expect(headers.get('X-Custom')).toBe('value');
    });

    it('uses correct HTTP method', async () => {
      await handler.proxy('org_1', makeRequest({ name: 'TOKEN', method: 'POST' }));

      const [, init] = mockFetch.mock.calls[0];
      expect(init.method).toBe('POST');
    });

    it('defaults to GET', async () => {
      await handler.proxy('org_1', makeRequest({ name: 'TOKEN' }));

      const [, init] = mockFetch.mock.calls[0];
      expect(init.method).toBe('GET');
    });

    it('does not send body for GET requests', async () => {
      await handler.proxy(
        'org_1',
        makeRequest({ name: 'TOKEN', method: 'GET', body: '{"should":"not send"}' }),
      );

      const [, init] = mockFetch.mock.calls[0];
      expect(init.body).toBeUndefined();
    });

    it('sends body for POST requests', async () => {
      await handler.proxy(
        'org_1',
        makeRequest({ name: 'TOKEN', method: 'POST', body: '{"data":"value"}' }),
      );

      const [, init] = mockFetch.mock.calls[0];
      expect(init.body).toBe('{"data":"value"}');
    });
  });

  describe('response handling', () => {
    beforeEach(() => {
      resolver = createMockResolver({ TOKEN: makeSecret('secret') });
      handler = new PrivilegedSecretHandler(resolver);
    });

    it('returns response status and body', async () => {
      mockFetch.mockResolvedValueOnce(
        new Response('{"result":"ok"}', { status: 201 }),
      );

      const result = await handler.proxy('org_1', makeRequest({ name: 'TOKEN' }));
      expect(result.status).toBe(201);
      expect(result.body).toBe('{"result":"ok"}');
    });

    it('returns response headers', async () => {
      mockFetch.mockResolvedValueOnce(
        new Response('ok', {
          status: 200,
          headers: { 'x-ratelimit-remaining': '42' },
        }),
      );

      const result = await handler.proxy('org_1', makeRequest({ name: 'TOKEN' }));
      expect(result.headers['x-ratelimit-remaining']).toBe('42');
    });

    it('returns 502 on fetch failure', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Connection refused'));

      const result = await handler.proxy('org_1', makeRequest({ name: 'TOKEN' }));
      expect(result.status).toBe(502);
      expect(JSON.parse(result.body).error).toContain('Connection refused');
    });
  });

  describe('caching', () => {
    it('caches resolved secrets', async () => {
      const cache = new SecretCache();
      resolver = createMockResolver({ TOKEN: makeSecret('secret') });
      handler = new PrivilegedSecretHandler(resolver, cache);

      await handler.proxy('org_1', makeRequest({ name: 'TOKEN' }));

      const cached = cache.get('org_1', 'TOKEN');
      expect(cached).not.toBeNull();
      expect(cached!.thumbprint).toBe('sha256:abc');
    });
  });
});
