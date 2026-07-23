// src/utils/MemoryCache.ts
//
// Small generic in-memory cache with per-entry expiration. Used by the
// reputation-scoring services (ReverseDnsService, NetworkAgeService,
// ResidentialProxyDetector) to cache expensive lookups (DNS, WHOIS/RDAP,
// optional third-party APIs) without hitting disk - these are all
// short/medium-lived, process-local caches, distinct from CacheService
// (which persists the main IP-check verdict cache to disk).
//
// Deliberately NOT persisted to disk: the values held here (PTR hostnames,
// ASN allocation dates, proxy-API verdicts) are cheap to re-fetch on
// restart and change infrequently, so there is no benefit worth the extra
// I/O - unlike checked_ips.json, whose whole purpose is to avoid re-running
// the entire paid/rate-limited API battery.
export class MemoryCache<T> {
  private store: Map<string, { value: T; expiresAt: number }> = new Map();
  private readonly ttlMs: number;
  private readonly maxEntries: number;

  constructor(ttlMs: number, maxEntries: number = 50000) {
    this.ttlMs = ttlMs;
    this.maxEntries = maxEntries;
  }

  get(key: string): T | null {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return null;
    }
    return entry.value;
  }

  set(key: string, value: T, ttlMsOverride?: number): void {
    // Cheap bound on unbounded growth: if we're at capacity, drop the
    // oldest-inserted entry (Map preserves insertion order) rather than
    // letting a long-running process grow this without limit. Only evict
    // when inserting a genuinely NEW key - updating an existing key doesn't
    // grow the map, so evicting on an update would needlessly throw away an
    // unrelated still-valid entry.
    if (!this.store.has(key) && this.store.size >= this.maxEntries) {
      const oldestKey = this.store.keys().next().value;
      if (oldestKey !== undefined) this.store.delete(oldestKey);
    }
    this.store.set(key, { value, expiresAt: Date.now() + (ttlMsOverride ?? this.ttlMs) });
  }

  has(key: string): boolean {
    return this.get(key) !== null;
  }

  delete(key: string): void {
    this.store.delete(key);
  }

  clear(): void {
    this.store.clear();
  }

  get size(): number {
    return this.store.size;
  }
}
