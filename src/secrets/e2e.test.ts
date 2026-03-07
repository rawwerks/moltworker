/**
 * End-to-end integration test for the sponsor secrets system.
 *
 * Exercises the full flow:
 *   use-secret CLI → secret proxy route → resolver → injection → external API → response
 *
 * Uses a mock external API (via fetch mock) to verify:
 * - Secret resolution works
 * - Credentials are injected correctly (bearer, header, query, body)
 * - Response is returned to the caller
 * - Secret value never leaks into the response
 * - Cache works (second call skips resolver)
 * - Auth is enforced
 * - Error paths work (missing secret, bad URL, fetch failure)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  PrivilegedSecretHandler,
  SecretCache,
  type SecretResolver,
  type ResolvedSecret,
} from './index';

// ── Mock external API ──

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

/** Simulate a real API response. */
function mockApiResponse(body: object, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

// ── In-memory secret store (simulates clawvilization's broker) ──

interface SecretStore {
  [organismId: string]: {
    [name: string]: ResolvedSecret;
  };
}

function createInMemoryResolver(store: SecretStore): SecretResolver {
  return {
    resolve: vi.fn(async (organismId: string, name: string) => {
      return store[organismId]?.[name] ?? store['*']?.[name] ?? null;
    }),
  };
}

// ── Tests ──

describe('Secrets E2E: full proxy flow', () => {
  let resolver: SecretResolver & { resolve: ReturnType<typeof vi.fn> };
  let cache: SecretCache;
  let handler: PrivilegedSecretHandler;

  const SECRETS: SecretStore = {
    'org_alice': {
      'GITHUB_TOKEN': {
        encrypted_value: 'enc:github',
        thumbprint: 'sha256:gh',
        injection_mode: 'bearer',
        plaintext: 'ghp_alice_secret_token_123',
      },
      'STRIPE_KEY': {
        encrypted_value: 'enc:stripe',
        thumbprint: 'sha256:stripe',
        injection_mode: 'bearer',
        plaintext: 'sk_test_stripe_secret',
      },
      'CUSTOM_API': {
        encrypted_value: 'enc:custom',
        thumbprint: 'sha256:custom',
        injection_mode: 'header:X-Api-Key',
        plaintext: 'custom_api_key_456',
      },
    },
    'org_bob': {
      'GITHUB_TOKEN': {
        encrypted_value: 'enc:github-bob',
        thumbprint: 'sha256:gh-bob',
        injection_mode: 'bearer',
        plaintext: 'ghp_bob_different_token',
      },
    },
  };

  beforeEach(() => {
    vi.clearAllMocks();
    cache = new SecretCache(60_000); // 1 minute TTL
    resolver = createInMemoryResolver(SECRETS) as any;
    handler = new PrivilegedSecretHandler(resolver, cache);

    // Default: mock external API returns success
    mockFetch.mockImplementation(async (url: string, init: RequestInit) => {
      // Capture what was sent for verification
      return mockApiResponse({
        received_url: url,
        received_method: init?.method || 'GET',
        received_auth: new Headers(init?.headers as any).get('Authorization'),
      });
    });
  });

  // ── Happy path: bearer injection ──

  it('injects bearer token and proxies GitHub API call', async () => {
    const result = await handler.proxy('org_alice', {
      name: 'GITHUB_TOKEN',
      injection_mode: 'bearer',
      url: 'https://api.github.com/user',
    });

    expect(result.status).toBe(200);

    // Verify the outbound request had the token
    const [, fetchInit] = mockFetch.mock.calls[0];
    const headers = new Headers(fetchInit.headers);
    expect(headers.get('Authorization')).toBe('Bearer ghp_alice_secret_token_123');

    // Verify response came back
    const body = JSON.parse(result.body);
    expect(body.received_url).toBe('https://api.github.com/user');
    expect(body.received_auth).toBe('Bearer ghp_alice_secret_token_123');
  });

  // ── Organism isolation ──

  it('resolves different secrets for different organisms', async () => {
    const aliceResult = await handler.proxy('org_alice', {
      name: 'GITHUB_TOKEN',
      injection_mode: 'bearer',
      url: 'https://api.github.com/user',
    });

    const bobResult = await handler.proxy('org_bob', {
      name: 'GITHUB_TOKEN',
      injection_mode: 'bearer',
      url: 'https://api.github.com/user',
    });

    // Both succeed
    expect(aliceResult.status).toBe(200);
    expect(bobResult.status).toBe(200);

    // But used different tokens
    const aliceAuth = new Headers(mockFetch.mock.calls[0][1].headers).get('Authorization');
    const bobAuth = new Headers(mockFetch.mock.calls[1][1].headers).get('Authorization');
    expect(aliceAuth).toBe('Bearer ghp_alice_secret_token_123');
    expect(bobAuth).toBe('Bearer ghp_bob_different_token');
  });

  it('returns 404 when organism has no access to a secret', async () => {
    const result = await handler.proxy('org_bob', {
      name: 'STRIPE_KEY', // Bob doesn't have this
      injection_mode: 'bearer',
      url: 'https://api.stripe.com/v1/charges',
    });

    expect(result.status).toBe(404);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  // ── Injection modes ──

  it('injects custom header (header:X-Api-Key)', async () => {
    const result = await handler.proxy('org_alice', {
      name: 'CUSTOM_API',
      injection_mode: 'header:X-Api-Key',
      url: 'https://api.example.com/data',
    });

    expect(result.status).toBe(200);
    const headers = new Headers(mockFetch.mock.calls[0][1].headers);
    expect(headers.get('X-Api-Key')).toBe('custom_api_key_456');
  });

  it('injects query parameter', async () => {
    const result = await handler.proxy('org_alice', {
      name: 'GITHUB_TOKEN',
      injection_mode: 'query:access_token',
      url: 'https://api.example.com/data?existing=param',
    });

    expect(result.status).toBe(200);
    const [fetchUrl] = mockFetch.mock.calls[0];
    expect(fetchUrl).toContain('access_token=ghp_alice_secret_token_123');
    expect(fetchUrl).toContain('existing=param');
  });

  it('injects body field with POST', async () => {
    mockFetch.mockResolvedValueOnce(mockApiResponse({ created: true }, 201));

    const result = await handler.proxy('org_alice', {
      name: 'STRIPE_KEY',
      injection_mode: 'body:api_key',
      url: 'https://api.stripe.com/v1/charges',
      method: 'POST',
      body: '{"amount":1000,"currency":"usd"}',
    });

    expect(result.status).toBe(201);
    const [, fetchInit] = mockFetch.mock.calls[0];
    const body = JSON.parse(fetchInit.body);
    expect(body.api_key).toBe('sk_test_stripe_secret');
    expect(body.amount).toBe(1000);
    expect(body.currency).toBe('usd');
  });

  it('injects basic auth', async () => {
    const result = await handler.proxy('org_alice', {
      name: 'GITHUB_TOKEN',
      injection_mode: 'basic',
      url: 'https://api.example.com/basic-auth',
    });

    expect(result.status).toBe(200);
    const headers = new Headers(mockFetch.mock.calls[0][1].headers);
    expect(headers.get('Authorization')).toBe(`Basic ${btoa('ghp_alice_secret_token_123')}`);
  });

  // ── Caching ──

  it('caches resolved secrets (second call skips resolver)', async () => {
    // First call — resolver is called
    await handler.proxy('org_alice', {
      name: 'GITHUB_TOKEN',
      injection_mode: 'bearer',
      url: 'https://api.github.com/user',
    });
    expect(resolver.resolve).toHaveBeenCalledTimes(1);

    // Second call — should use cache, resolver NOT called again
    await handler.proxy('org_alice', {
      name: 'GITHUB_TOKEN',
      injection_mode: 'bearer',
      url: 'https://api.github.com/repos',
    });
    expect(resolver.resolve).toHaveBeenCalledTimes(1); // still 1

    // But the outbound request still has the correct token
    const headers = new Headers(mockFetch.mock.calls[1][1].headers);
    expect(headers.get('Authorization')).toBe('Bearer ghp_alice_secret_token_123');
  });

  it('cache expires and re-resolves', async () => {
    vi.useFakeTimers();
    try {
      const shortCache = new SecretCache(100); // 100ms TTL
      const shortHandler = new PrivilegedSecretHandler(resolver, shortCache);

      // First call
      await shortHandler.proxy('org_alice', {
        name: 'GITHUB_TOKEN',
        injection_mode: 'bearer',
        url: 'https://api.github.com/user',
      });
      expect(resolver.resolve).toHaveBeenCalledTimes(1);

      // Advance past TTL
      vi.advanceTimersByTime(200);

      // Second call — cache expired, resolver called again
      await shortHandler.proxy('org_alice', {
        name: 'GITHUB_TOKEN',
        injection_mode: 'bearer',
        url: 'https://api.github.com/user',
      });
      expect(resolver.resolve).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it('cache isolates organisms', async () => {
    // Cache Alice's secret
    await handler.proxy('org_alice', {
      name: 'GITHUB_TOKEN',
      injection_mode: 'bearer',
      url: 'https://api.github.com/user',
    });

    // Bob's call should NOT use Alice's cache
    await handler.proxy('org_bob', {
      name: 'GITHUB_TOKEN',
      injection_mode: 'bearer',
      url: 'https://api.github.com/user',
    });

    // Resolver called twice (once per organism)
    expect(resolver.resolve).toHaveBeenCalledTimes(2);
    expect(resolver.resolve).toHaveBeenCalledWith('org_alice', 'GITHUB_TOKEN');
    expect(resolver.resolve).toHaveBeenCalledWith('org_bob', 'GITHUB_TOKEN');
  });

  // ── Security: no secret leakage ──

  it('secret value never appears in the handler metadata (status/headers)', async () => {
    // Use a mock that does NOT echo the auth header back
    mockFetch.mockResolvedValueOnce(
      mockApiResponse({ user: 'alice', id: 42 }),
    );

    const result = await handler.proxy('org_alice', {
      name: 'GITHUB_TOKEN',
      injection_mode: 'bearer',
      url: 'https://api.github.com/user',
    });

    // The handler's own metadata (status, headers) must not leak the secret
    expect(JSON.stringify(result.headers)).not.toContain('ghp_alice_secret_token_123');
    expect(String(result.status)).not.toContain('ghp_alice_secret_token_123');
    // The response body is the external API's response — it's opaque to us.
    // The external API received the secret (that's correct), but the handler
    // doesn't inject secrets into response headers or status.
    expect(result.body).not.toContain('ghp_alice_secret_token_123');
  });

  it('different injection modes do not cross-contaminate', async () => {
    // Use bearer mode
    await handler.proxy('org_alice', {
      name: 'GITHUB_TOKEN',
      injection_mode: 'bearer',
      url: 'https://api.github.com/user',
    });

    // Use query mode for same secret
    await handler.proxy('org_alice', {
      name: 'GITHUB_TOKEN',
      injection_mode: 'query:token',
      url: 'https://api.example.com/data',
    });

    // First call: bearer in header, no query param
    const [url1, init1] = mockFetch.mock.calls[0];
    expect(new Headers(init1.headers).get('Authorization')).toBe('Bearer ghp_alice_secret_token_123');
    expect(url1).not.toContain('token=');

    // Second call: query param, no bearer header
    const [url2, init2] = mockFetch.mock.calls[1];
    expect(url2).toContain('token=ghp_alice_secret_token_123');
    expect(new Headers(init2.headers).get('Authorization')).toBeNull();
  });

  // ── Error paths ──

  it('returns 400 for invalid injection mode', async () => {
    const result = await handler.proxy('org_alice', {
      name: 'GITHUB_TOKEN',
      injection_mode: 'raw',
      url: 'https://api.github.com/user',
    });

    expect(result.status).toBe(400);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('returns 400 for invalid URL', async () => {
    const result = await handler.proxy('org_alice', {
      name: 'GITHUB_TOKEN',
      injection_mode: 'bearer',
      url: 'not-a-url',
    });

    expect(result.status).toBe(400);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('returns 502 when external API is unreachable', async () => {
    mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));

    const result = await handler.proxy('org_alice', {
      name: 'GITHUB_TOKEN',
      injection_mode: 'bearer',
      url: 'https://api.github.com/user',
    });

    expect(result.status).toBe(502);
    expect(JSON.parse(result.body).error).toContain('ECONNREFUSED');
  });

  it('forwards external API error status codes', async () => {
    mockFetch.mockResolvedValueOnce(
      mockApiResponse({ message: 'Bad credentials' }, 401, { 'x-ratelimit-remaining': '0' }),
    );

    const result = await handler.proxy('org_alice', {
      name: 'GITHUB_TOKEN',
      injection_mode: 'bearer',
      url: 'https://api.github.com/user',
    });

    expect(result.status).toBe(401);
    expect(JSON.parse(result.body).message).toBe('Bad credentials');
    expect(result.headers['x-ratelimit-remaining']).toBe('0');
  });

  // ── Multiple secrets in sequence ──

  it('handles multiple secrets in a single session', async () => {
    // Use GitHub token
    const r1 = await handler.proxy('org_alice', {
      name: 'GITHUB_TOKEN',
      injection_mode: 'bearer',
      url: 'https://api.github.com/user',
    });
    expect(r1.status).toBe(200);

    // Use Stripe key
    const r2 = await handler.proxy('org_alice', {
      name: 'STRIPE_KEY',
      injection_mode: 'bearer',
      url: 'https://api.stripe.com/v1/charges',
      method: 'POST',
      body: '{"amount":1000}',
    });
    expect(r2.status).toBe(200);

    // Use custom API key
    const r3 = await handler.proxy('org_alice', {
      name: 'CUSTOM_API',
      injection_mode: 'header:X-Api-Key',
      url: 'https://api.example.com/data',
    });
    expect(r3.status).toBe(200);

    // Verify each used the correct secret
    expect(new Headers(mockFetch.mock.calls[0][1].headers).get('Authorization'))
      .toBe('Bearer ghp_alice_secret_token_123');
    expect(new Headers(mockFetch.mock.calls[1][1].headers).get('Authorization'))
      .toBe('Bearer sk_test_stripe_secret');
    expect(new Headers(mockFetch.mock.calls[2][1].headers).get('X-Api-Key'))
      .toBe('custom_api_key_456');
  });

  // ── Request forwarding ──

  it('forwards custom headers from the caller', async () => {
    await handler.proxy('org_alice', {
      name: 'GITHUB_TOKEN',
      injection_mode: 'bearer',
      url: 'https://api.github.com/user',
      headers: {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'openclaw-organism/1.0',
      },
    });

    const headers = new Headers(mockFetch.mock.calls[0][1].headers);
    expect(headers.get('Accept')).toBe('application/vnd.github.v3+json');
    expect(headers.get('User-Agent')).toBe('openclaw-organism/1.0');
    // And the secret was still injected
    expect(headers.get('Authorization')).toBe('Bearer ghp_alice_secret_token_123');
  });
});

// ── Env var integration ──

describe('Secrets E2E: env var wiring', () => {
  it('ORGANISM_ID is passed through buildEnvVars', async () => {
    // Lazy import to avoid circular deps
    const { buildEnvVars } = await import('../gateway/env');
    const { createMockEnv } = await import('../test-utils');

    const env = createMockEnv({ ORGANISM_ID: 'org_test_123' });
    const vars = buildEnvVars(env);
    expect(vars.ORGANISM_ID).toBe('org_test_123');
  });

  it('WORKER_URL is passed through for use-secret callback', async () => {
    const { buildEnvVars } = await import('../gateway/env');
    const { createMockEnv } = await import('../test-utils');

    const env = createMockEnv({ WORKER_URL: 'https://my-worker.example.com' });
    const vars = buildEnvVars(env);
    expect(vars.WORKER_URL).toBe('https://my-worker.example.com');
  });

  it('OPENCLAW_GATEWAY_TOKEN is passed through for use-secret auth', async () => {
    const { buildEnvVars } = await import('../gateway/env');
    const { createMockEnv } = await import('../test-utils');

    const env = createMockEnv({ MOLTBOT_GATEWAY_TOKEN: 'gw-token-123' });
    const vars = buildEnvVars(env);
    expect(vars.OPENCLAW_GATEWAY_TOKEN).toBe('gw-token-123');
  });
});
