/**
 * Secret proxy route — called by the `use-secret` CLI stub inside the sandbox.
 *
 * Auth: Gateway token (same as MOLTBOT_GATEWAY_TOKEN), not CF Access.
 * The sandbox knows the gateway token (passed as OPENCLAW_GATEWAY_TOKEN).
 *
 * POST /secrets/proxy
 * Body: { name, injection_mode, url, method?, headers?, body? }
 * Header: Authorization: Bearer <gateway-token>
 *
 * The Worker resolves the secret from the broker, injects it into the
 * outbound request, makes the call, and returns the response. The sandbox
 * never sees the plaintext secret value.
 */

import { Hono } from 'hono';
import type { AppEnv } from '../types.js';
import { PrivilegedSecretHandler, type SecretProxyRequest, type SecretResolver } from '../secrets/index.js';
import { SecretCache } from '../secrets/cache.js';

// Singleton cache shared across requests within this Worker instance
const secretCache = new SecretCache();

/**
 * Placeholder resolver — returns null until wired to clawvilization's broker API.
 * Replace this with an HTTP client to the broker when the API is ready.
 */
const placeholderResolver: SecretResolver = {
  async resolve(_organismId: string, _name: string) {
    return null;
  },
};

// Allow injection of a custom resolver for testing or when broker is ready
let activeResolver: SecretResolver = placeholderResolver;

export function setSecretResolver(resolver: SecretResolver): void {
  activeResolver = resolver;
}

export function getSecretCache(): SecretCache {
  return secretCache;
}

const secrets = new Hono<AppEnv>();

// Auth middleware: verify gateway token
secrets.use('*', async (c, next) => {
  const token = c.env.MOLTBOT_GATEWAY_TOKEN;
  if (!token) {
    return c.json({ error: 'Secret proxy not configured (no gateway token)' }, 503);
  }

  const auth = c.req.header('Authorization');
  const providedToken = auth?.startsWith('Bearer ') ? auth.slice(7) : null;

  if (!providedToken || providedToken !== token) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  return next();
});

// POST /secrets/proxy
secrets.post('/proxy', async (c) => {
  const body = await c.req.json<SecretProxyRequest & { organism_id?: string }>();

  // organism_id comes from the container's environment or is derived from the sandbox
  // For now, use a placeholder — the broker integration will provide real organism IDs
  const organismId = body.organism_id || 'default';

  const handler = new PrivilegedSecretHandler(activeResolver, secretCache);
  const result = await handler.proxy(organismId, body);

  return c.json(result, result.status as any);
});

// GET /secrets/available — list secret names (no values)
secrets.get('/available', async (c) => {
  // Placeholder until broker integration
  return c.json({ names: [], message: 'Broker integration pending' });
});

export { secrets };
