import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { SecretCache } from './cache';

describe('SecretCache', () => {
  let cache: SecretCache;

  beforeEach(() => {
    cache = new SecretCache(1000); // 1 second TTL for tests
  });

  const sampleSecret = {
    encrypted_value: 'base64ciphertext',
    thumbprint: 'sha256:abc',
    injection_mode: 'bearer',
  };

  it('returns null for missing entries', () => {
    expect(cache.get('org_1', 'GITHUB_TOKEN')).toBeNull();
  });

  it('stores and retrieves a secret', () => {
    cache.set('org_1', 'GITHUB_TOKEN', sampleSecret);
    const result = cache.get('org_1', 'GITHUB_TOKEN');
    expect(result).not.toBeNull();
    expect(result!.thumbprint).toBe('sha256:abc');
    expect(result!.injection_mode).toBe('bearer');
  });

  it('isolates by organism ID', () => {
    cache.set('org_1', 'TOKEN', sampleSecret);
    expect(cache.get('org_2', 'TOKEN')).toBeNull();
  });

  it('isolates by secret name', () => {
    cache.set('org_1', 'TOKEN_A', sampleSecret);
    expect(cache.get('org_1', 'TOKEN_B')).toBeNull();
  });

  it('expires entries after TTL', () => {
    vi.useFakeTimers();
    try {
      cache.set('org_1', 'TOKEN', sampleSecret);
      expect(cache.get('org_1', 'TOKEN')).not.toBeNull();

      vi.advanceTimersByTime(1001);
      expect(cache.get('org_1', 'TOKEN')).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it('does not expire before TTL', () => {
    vi.useFakeTimers();
    try {
      cache.set('org_1', 'TOKEN', sampleSecret);
      vi.advanceTimersByTime(999);
      expect(cache.get('org_1', 'TOKEN')).not.toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it('invalidates a specific secret', () => {
    cache.set('org_1', 'TOKEN_A', sampleSecret);
    cache.set('org_1', 'TOKEN_B', sampleSecret);
    cache.invalidate('org_1', 'TOKEN_A');
    expect(cache.get('org_1', 'TOKEN_A')).toBeNull();
    expect(cache.get('org_1', 'TOKEN_B')).not.toBeNull();
  });

  it('invalidates all secrets for an organism', () => {
    cache.set('org_1', 'TOKEN_A', sampleSecret);
    cache.set('org_1', 'TOKEN_B', sampleSecret);
    cache.set('org_2', 'TOKEN_A', sampleSecret);
    cache.invalidateAll('org_1');
    expect(cache.get('org_1', 'TOKEN_A')).toBeNull();
    expect(cache.get('org_1', 'TOKEN_B')).toBeNull();
    expect(cache.get('org_2', 'TOKEN_A')).not.toBeNull();
  });

  it('clears the entire cache', () => {
    cache.set('org_1', 'A', sampleSecret);
    cache.set('org_2', 'B', sampleSecret);
    expect(cache.size).toBe(2);
    cache.clear();
    expect(cache.size).toBe(0);
  });

  it('overwrites existing entries', () => {
    cache.set('org_1', 'TOKEN', sampleSecret);
    cache.set('org_1', 'TOKEN', { ...sampleSecret, thumbprint: 'sha256:new' });
    expect(cache.get('org_1', 'TOKEN')!.thumbprint).toBe('sha256:new');
  });

  it('uses default TTL of 5 minutes', () => {
    const defaultCache = new SecretCache();
    vi.useFakeTimers();
    try {
      defaultCache.set('org_1', 'TOKEN', sampleSecret);
      vi.advanceTimersByTime(4 * 60 * 1000); // 4 minutes
      expect(defaultCache.get('org_1', 'TOKEN')).not.toBeNull();
      vi.advanceTimersByTime(2 * 60 * 1000); // +2 more = 6 minutes total
      expect(defaultCache.get('org_1', 'TOKEN')).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });
});
