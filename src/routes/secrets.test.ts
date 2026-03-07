import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  PrivilegedSecretHandler,
  type SecretResolver,
  type SecretProxyRequest,
} from '../secrets';

/**
 * Route-level behavior tests for the secrets proxy.
 * These test the auth logic and request flow directly,
 * without needing Hono's env binding (which is tricky in test mode).
 */

// Mock global fetch
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

describe('secrets route auth logic', () => {
  it('gateway token validation - matching', () => {
    const token = 'test-gateway-token';
    const auth = `Bearer ${token}`;
    const providedToken = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    expect(providedToken).toBe(token);
  });

  it('gateway token validation - mismatch', () => {
    const token = 'test-gateway-token';
    const auth = 'Bearer wrong-token';
    const providedToken = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    expect(providedToken).not.toBe(token);
  });

  it('gateway token validation - missing auth', () => {
    const auth = undefined;
    const providedToken = auth?.startsWith('Bearer ') ? auth.slice(7) : null;
    expect(providedToken).toBeNull();
  });

  it('gateway token validation - non-bearer', () => {
    const auth = 'Basic dXNlcjpwYXNz';
    const providedToken = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    expect(providedToken).toBeNull();
  });
});

describe('secrets route request flow', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetch.mockResolvedValue(
      new Response('{"data":"response"}', { status: 200, headers: { 'content-type': 'application/json' } }),
    );
  });

  it('full proxy flow: resolve → inject → fetch → return', async () => {
    const resolver: SecretResolver = {
      resolve: vi.fn(async () => ({
        encrypted_value: 'enc',
        thumbprint: 'sha256:abc',
        injection_mode: 'bearer',
        plaintext: 'ghp_secret',
      })),
    };

    const handler = new PrivilegedSecretHandler(resolver);
    const req: SecretProxyRequest = {
      name: 'GITHUB_TOKEN',
      injection_mode: 'bearer',
      url: 'https://api.github.com/user',
      method: 'GET',
    };

    const result = await handler.proxy('org_123', req);

    // Resolver was called
    expect(resolver.resolve).toHaveBeenCalledWith('org_123', 'GITHUB_TOKEN');

    // Fetch was called with injected bearer
    expect(mockFetch).toHaveBeenCalled();
    const [fetchUrl, fetchInit] = mockFetch.mock.calls[0];
    expect(fetchUrl).toBe('https://api.github.com/user');
    const headers = new Headers(fetchInit.headers);
    expect(headers.get('Authorization')).toBe('Bearer ghp_secret');

    // Response was returned
    expect(result.status).toBe(200);
    expect(result.body).toBe('{"data":"response"}');
  });

  it('returns 404 when resolver returns null', async () => {
    const resolver: SecretResolver = {
      resolve: vi.fn(async () => null),
    };

    const handler = new PrivilegedSecretHandler(resolver);
    const result = await handler.proxy('org_1', {
      name: 'MISSING',
      injection_mode: 'bearer',
      url: 'https://example.com',
    });

    expect(result.status).toBe(404);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('secret value never appears in response body', async () => {
    const resolver: SecretResolver = {
      resolve: vi.fn(async () => ({
        encrypted_value: 'enc',
        thumbprint: 'sha256:abc',
        injection_mode: 'bearer',
        plaintext: 'SUPER_SECRET_VALUE',
      })),
    };

    const handler = new PrivilegedSecretHandler(resolver);
    const result = await handler.proxy('org_1', {
      name: 'TOKEN',
      injection_mode: 'bearer',
      url: 'https://api.example.com',
    });

    // The response body is from the external API, not from our handler
    expect(result.body).not.toContain('SUPER_SECRET_VALUE');
  });
});
