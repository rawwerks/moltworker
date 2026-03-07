/**
 * SecretCache — TTL-based in-memory cache for resolved secrets.
 *
 * Prevents round-tripping to the broker on every `use-secret` call.
 * Short TTL ensures rotations propagate quickly.
 */

export interface CachedSecret {
  encrypted_value: string; // base64-encoded ciphertext
  thumbprint: string;
  injection_mode: string;
  /** Plaintext cached in Worker memory (trusted, short-lived). */
  plaintext?: string;
  cached_at: number; // Date.now()
}

const DEFAULT_TTL_MS = 5 * 60 * 1000; // 5 minutes

export class SecretCache {
  private cache = new Map<string, CachedSecret>();
  private ttlMs: number;

  constructor(ttlMs: number = DEFAULT_TTL_MS) {
    this.ttlMs = ttlMs;
  }

  /** Build a cache key from organism + secret name. */
  private key(organismId: string, name: string): string {
    return `${organismId}:${name}`;
  }

  /** Get a cached secret if it exists and hasn't expired. */
  get(organismId: string, name: string): CachedSecret | null {
    const entry = this.cache.get(this.key(organismId, name));
    if (!entry) return null;
    if (Date.now() - entry.cached_at > this.ttlMs) {
      this.cache.delete(this.key(organismId, name));
      return null;
    }
    return entry;
  }

  /** Store a resolved secret in the cache. */
  set(organismId: string, name: string, secret: Omit<CachedSecret, 'cached_at'>): void {
    this.cache.set(this.key(organismId, name), {
      ...secret,
      cached_at: Date.now(),
    });
  }

  /** Invalidate a specific secret. */
  invalidate(organismId: string, name: string): void {
    this.cache.delete(this.key(organismId, name));
  }

  /** Invalidate all secrets for an organism. */
  invalidateAll(organismId: string): void {
    const prefix = `${organismId}:`;
    for (const key of this.cache.keys()) {
      if (key.startsWith(prefix)) {
        this.cache.delete(key);
      }
    }
  }

  /** Clear the entire cache. */
  clear(): void {
    this.cache.clear();
  }

  /** Number of entries in the cache. */
  get size(): number {
    return this.cache.size;
  }
}
