/**
 * Privileged secret handler — resolves secrets from the broker and proxies
 * external API calls with injected credentials.
 *
 * The sandbox never sees plaintext secret values. Instead:
 * 1. Agent calls `use-secret` CLI stub in the sandbox
 * 2. The stub sends a request to the Worker's /api/secrets/proxy endpoint
 * 3. This handler resolves the secret from the broker
 * 4. Makes the external API call with the secret injected
 * 5. Returns the response to the sandbox
 *
 * Injection modes:
 * - bearer: Authorization: Bearer <secret>
 * - basic: Authorization: Basic <base64(secret)>
 * - header:<name>: Custom header with secret value
 * - query:<param>: Query parameter with secret value
 * - body:<field>: JSON body field with secret value
 */

import { SecretCache } from './cache.js';

/** Request from the `use-secret` CLI stub in the sandbox. */
export interface SecretProxyRequest {
  /** Secret name (e.g., GITHUB_TOKEN) */
  name: string;
  /** Injection mode (e.g., bearer, header:X-Api-Key) */
  injection_mode: string;
  /** Target URL to call with injected secret */
  url: string;
  /** HTTP method (default: GET) */
  method?: string;
  /** Request headers to forward */
  headers?: Record<string, string>;
  /** Request body to forward */
  body?: string;
}

export interface SecretProxyResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

/** Interface for the broker client that resolves secrets. */
export interface SecretResolver {
  resolve(organismId: string, name: string): Promise<ResolvedSecret | null>;
}

export interface ResolvedSecret {
  encrypted_value: string;
  thumbprint: string;
  injection_mode: string;
  /** The decrypted plaintext value — only available in the Worker's trusted context. */
  plaintext: string;
}

export class PrivilegedSecretHandler {
  private cache: SecretCache;
  private resolver: SecretResolver;

  constructor(resolver: SecretResolver, cache?: SecretCache) {
    this.resolver = resolver;
    this.cache = cache ?? new SecretCache();
  }

  /**
   * Handle a secret proxy request: resolve the secret, inject it into
   * the outbound request, make the call, return the response.
   */
  async proxy(organismId: string, req: SecretProxyRequest): Promise<SecretProxyResponse> {
    // 1. Validate the request
    const validationError = this.validateRequest(req);
    if (validationError) {
      return { status: 400, headers: {}, body: JSON.stringify({ error: validationError }) };
    }

    // 2. Resolve the secret (cache-first)
    const secret = await this.resolveSecret(organismId, req.name);
    if (!secret) {
      return {
        status: 404,
        headers: {},
        body: JSON.stringify({ error: `Secret '${req.name}' not found or not available` }),
      };
    }

    // 3. Build the outbound request with injected secret
    const outboundRequest = this.buildOutboundRequest(req, secret.plaintext);

    // 4. Make the external call
    try {
      const response = await fetch(outboundRequest.url, outboundRequest.init);

      // 5. Collect response
      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        responseHeaders[key] = value;
      });

      const responseBody = await response.text();

      return {
        status: response.status,
        headers: responseHeaders,
        body: responseBody,
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown fetch error';
      return {
        status: 502,
        headers: {},
        body: JSON.stringify({ error: `Failed to reach target: ${message}` }),
      };
    }
  }

  private validateRequest(req: SecretProxyRequest): string | null {
    if (!req.name || typeof req.name !== 'string') {
      return 'Missing or invalid secret name';
    }
    if (!req.injection_mode || typeof req.injection_mode !== 'string') {
      return 'Missing or invalid injection_mode';
    }
    if (!req.url || typeof req.url !== 'string') {
      return 'Missing or invalid target URL';
    }

    // Validate URL
    try {
      new URL(req.url);
    } catch {
      return 'Invalid target URL';
    }

    // Validate injection mode
    const validModes = ['bearer', 'basic'];
    const prefixedModes = ['header:', 'query:', 'body:'];
    const isValid =
      validModes.includes(req.injection_mode) ||
      prefixedModes.some((p) => req.injection_mode.startsWith(p));

    if (!isValid) {
      return `Invalid injection_mode: ${req.injection_mode}`;
    }

    return null;
  }

  private async resolveSecret(organismId: string, name: string): Promise<ResolvedSecret | null> {
    // Check cache first — Worker memory is trusted and short-lived
    const cached = this.cache.get(organismId, name);
    if (cached?.plaintext) {
      return {
        encrypted_value: cached.encrypted_value,
        thumbprint: cached.thumbprint,
        injection_mode: cached.injection_mode,
        plaintext: cached.plaintext,
      };
    }

    const secret = await this.resolver.resolve(organismId, name);
    if (!secret) return null;

    // Cache including plaintext (Worker memory is trusted)
    this.cache.set(organismId, name, {
      encrypted_value: secret.encrypted_value,
      thumbprint: secret.thumbprint,
      injection_mode: secret.injection_mode,
      plaintext: secret.plaintext,
    });

    return secret;
  }

  private buildOutboundRequest(
    req: SecretProxyRequest,
    plaintext: string,
  ): { url: string; init: RequestInit } {
    const method = req.method?.toUpperCase() || 'GET';
    const headers = new Headers(req.headers || {});
    let url = req.url;
    let body: string | undefined = req.body;

    const mode = req.injection_mode;

    if (mode === 'bearer') {
      headers.set('Authorization', `Bearer ${plaintext}`);
    } else if (mode === 'basic') {
      headers.set('Authorization', `Basic ${btoa(plaintext)}`);
    } else if (mode.startsWith('header:')) {
      const headerName = mode.slice('header:'.length);
      headers.set(headerName, plaintext);
    } else if (mode.startsWith('query:')) {
      const paramName = mode.slice('query:'.length);
      const parsed = new URL(url);
      parsed.searchParams.set(paramName, plaintext);
      url = parsed.toString();
    } else if (mode.startsWith('body:')) {
      const fieldName = mode.slice('body:'.length);
      const parsed = body ? JSON.parse(body) : {};
      parsed[fieldName] = plaintext;
      body = JSON.stringify(parsed);
      if (!headers.has('Content-Type')) {
        headers.set('Content-Type', 'application/json');
      }
    }

    return {
      url,
      init: {
        method,
        headers,
        body: method !== 'GET' && method !== 'HEAD' ? body : undefined,
      },
    };
  }
}
