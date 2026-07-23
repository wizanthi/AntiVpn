import { CachedIpData, IpCheckResult } from '../types';
import { Logger } from './Logger';
import { StorageAdapter } from '../services/StorageAdapter';

// Cache service for IP check results - singleton pattern.
//
// This is the hot-path "IP -> small LRU cache -> ... -> return" front door:
// a bounded least-recently-used cache (default 5000 entries, configurable
// via config.json's ipcheck.cache_max_entries) in front of the much more
// expensive Layer 0.5-3.75 checks in IpChecker (local range/ASN lookups,
// and - on a miss - up to 15 external API calls). Previously an unbounded
// Map pruned only by TTL, which meant a long-running server seeing many
// thousands of distinct player IPs would grow this cache without limit
// between TTL sweeps. A JS Map preserves insertion order, so the standard
// delete-then-reinsert-on-access idiom below turns it into an O(1) LRU:
// the least-recently-touched entry is always whatever's first in
// iteration order, and evicting it is a single `.next().value` + delete.
export class CacheService {
  private static instance: CacheService;
  private cache: Map<string, CachedIpData>;
  private storageAdapter: StorageAdapter | null = null;
  private ttlMs: number;
  private maxEntries: number = 5000;
  private logger: Logger;
  // Guards against overlapping writes: now that saveToDisk() is
  // fire-and-forget async (see below), a burst of connections could each
  // roll the 5% dice and kick off their own concurrent write to the same
  // file before the previous one finishes, corrupting/interleaving it.
  private isSaving: boolean = false;
  private saveAgainAfter: boolean = false;
  // Resolves when the in-flight write (and any write chained after it via
  // saveAgainAfter) finishes. Lets stop() on shutdown actually wait for the
  // last save instead of racing it against storageAdapter.close().
  private savePromise: Promise<void> = Promise.resolve();

  private constructor() {
    this.logger = Logger.getInstance();
    this.cache = new Map();
    this.ttlMs = 24 * 60 * 60 * 1000; // 24 hours default TTL
  }

  static getInstance(): CacheService {
    if (!CacheService.instance) {
      CacheService.instance = new CacheService();
    }
    return CacheService.instance;
  }

  // Set cache TTL in hours
  setTTL(hours: number): void {
    this.ttlMs = hours * 60 * 60 * 1000;
  }

  // Bounds the LRU - if the cache is currently over the new limit (e.g.
  // an operator lowers it at runtime), trims the oldest entries down to it
  // immediately rather than waiting for the next set() calls to do it one
  // at a time.
  setMaxEntries(max: number): void {
    this.maxEntries = Math.max(1, max);
    while (this.cache.size > this.maxEntries) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey === undefined) break;
      this.cache.delete(oldestKey);
    }
  }

  // Get cached IP check result
  get(ip: string): IpCheckResult | null {
    const cached = this.cache.get(ip);

    if (!cached) return null;

    // Check TTL expiration - a per-entry TTL (set for SOFT-confidence
    // results, so a quarantine verdict is re-evaluated much sooner than a
    // hard/clean one) wins over the global default when present.
    if (Date.now() - cached.timestamp > (cached.ttlMs ?? this.ttlMs)) {
      this.cache.delete(ip);
      return null;
    }

    // Mark as most-recently-used: delete + reinsert moves this key to the
    // end of the Map's iteration order, so the LRU eviction in set() below
    // never evicts an entry that's still being actively read.
    this.cache.delete(ip);
    this.cache.set(ip, cached);

    return { ...cached.result, cached: true };
  }

  // Set IP check result in cache. `ttlMs` (optional) bounds THIS entry
  // tighter than the global TTL - used for SOFT-confidence (quarantine)
  // verdicts, which must come back up for a full re-check quickly instead
  // of re-firing off a 24h-cached possibly-wrong verdict on every
  // reconnect. Never widens the global TTL.
  set(ip: string, result: IpCheckResult, ttlMs?: number): void {
    // Evict the least-recently-used entry first if we're at capacity and
    // this is a genuinely new key (an update to an existing key doesn't
    // grow the cache, so it never needs to evict anything).
    if (!this.cache.has(ip) && this.cache.size >= this.maxEntries) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) this.cache.delete(oldestKey);
    } else if (this.cache.has(ip)) {
      // Re-inserting below already moves it to the end - just drop the
      // stale position first so the Map doesn't keep the old ordering.
      this.cache.delete(ip);
    }
    this.cache.set(ip, {
      result,
      timestamp: Date.now(),
      ...(ttlMs !== undefined && ttlMs > 0 ? { ttlMs: Math.min(ttlMs, this.ttlMs) } : {})
    });

    // Save to disk periodically (5% chance)
    if (Math.random() < 0.05) {
      this.saveToDisk();
    }
  }

  // Check if IP exists in cache and is valid
  has(ip: string): boolean {
    const cached = this.cache.get(ip);
    if (!cached) return false;
    return (Date.now() - cached.timestamp) <= (cached.ttlMs ?? this.ttlMs);
  }

  // Drop one entry - used by the quarantine re-verification worker when a
  // soft ban is refuted, so the next connection from this IP gets a fresh
  // full check instead of the cached (wrong) quarantine verdict.
  delete(ip: string): void {
    this.cache.delete(ip);
  }

  // Get all cached entries
  getAll(): Record<string, CachedIpData> {
    const result: Record<string, CachedIpData> = {};
    this.cache.forEach((value, key) => {
      result[key] = value;
    });
    return result;
  }

  // Load cache via the configured storage backend (file/sqlite/mysql - see
  // StorageAdapter.ts). Called once at bot startup.
  async initStorage(adapter: StorageAdapter): Promise<void> {
    this.storageAdapter = adapter;
    try {
      const data = await adapter.read('checked_ips') as Record<string, CachedIpData> | null;
      if (data) {
        // Sort newest-first so that if the persisted store holds more
        // entries than maxEntries (e.g. left over from before this bound
        // existed), the ones actually kept are the most recently seen -
        // not an arbitrary object-key-order subset.
        const entries = Object.entries(data)
          .map(([ip, cached]) => [ip, cached as CachedIpData] as const)
          .filter(([, entry]) => Date.now() - entry.timestamp <= this.ttlMs)
          .sort((a, b) => a[1].timestamp - b[1].timestamp); // oldest-first for insertion, so most-recent ends up last (most-recently-used)
        const kept = entries.slice(-this.maxEntries);
        for (const [ip, entry] of kept) {
          this.cache.set(ip, entry);
        }
        this.logger.info(`Cache loaded: ${this.cache.size} entries${entries.length > kept.length ? ` (${entries.length - kept.length} older entries dropped, over the ${this.maxEntries}-entry limit)` : ''}`);
      }
    } catch (error) {
      this.logger.error('Failed to load cache from storage', error);
    }
  }

  // Save cache via the configured storage backend. Fire-and-forget for
  // hot-path callers (the return value is ignorable), but returns a promise
  // that resolves once the write - and any write chained after it via
  // saveAgainAfter - actually lands, so shutdown can await the final save
  // instead of closing the storage backend out from under it.
  saveToDisk(): Promise<void> {
    if (this.isSaving) {
      // A write is already in flight - just remember to run one more save
      // right after it finishes, instead of starting a second concurrent
      // write to the same store. Callers who need to know when *that*
      // follow-up save lands (e.g. shutdown) still get an accurate promise
      // back via savePromise, which the in-flight write's chain updates.
      this.saveAgainAfter = true;
      return this.savePromise;
    }
    if (!this.storageAdapter) return Promise.resolve(); // not initialized yet

    const data: Record<string, CachedIpData> = {};
    this.cache.forEach((value, key) => {
      data[key] = value;
    });

    this.isSaving = true;
    // Async write: this fires from set() on ~5% of every single
    // per-connection cache write, so a blocking write here would
    // periodically stall the whole event loop - including other players'
    // in-flight connection checks - for however long it takes to persist
    // the entire cache.
    this.savePromise = this.storageAdapter.write('checked_ips', data)
      .then(() => {
        this.isSaving = false;
        if (this.saveAgainAfter) {
          this.saveAgainAfter = false;
          return this.saveToDisk();
        }
      })
      .catch((error) => {
        this.isSaving = false;
        this.logger.error('Failed to save cache to storage', error);
        if (this.saveAgainAfter) {
          this.saveAgainAfter = false;
          return this.saveToDisk();
        }
      });
    return this.savePromise;
  }

  // Current entry count without materializing a full copy (getAll() builds
  // a whole Record just to be counted - wasteful on a large cache).
  size(): number {
    return this.cache.size;
  }

  // Clear all cached data
  clear(): void {
    this.cache.clear();
    this.saveToDisk();
  }
}