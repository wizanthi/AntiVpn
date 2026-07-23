// src/services/IpReputationStore.ts
//
// Per-IP historical reputation - backs the "IP Reputation" weighted signal
// (+25 by default) in RiskScoringEngine and one of the independent signals
// ResidentialProxyDetector looks at.
//
// This is distinct from CacheService (data/checked_ips.json), which caches
// the *latest* verdict for an IP with a TTL for fast lookup. This store
// instead accumulates a small amount of history across every time an IP has
// been seen/checked - "has this exact IP been banned before, or repeatedly
// flagged" is a different, longer-memory question than "what did the last
// check say", and matters most for the common case of a player reconnecting
// from the same IP many times.
//
// Same lightweight JSON-file, in-memory-plus-debounced-write pattern as the
// rest of this project's "storage layer" (ListManager, CacheService,
// NetworkReputationStore) - see those files for the rationale.
import { IpReputationRecord } from '../types';
import { Logger } from '../utils/Logger';
import { StorageAdapter } from './StorageAdapter';

interface IpReputationScoreResult {
  bad: boolean;
  good: boolean; // enough clean history to justify a small negative adjustment
  significant: boolean;
  score: number; // 0-100
  record: IpReputationRecord | null;
}

const MAX_RECORDS = 100000; // bound memory/disk use on long-running servers

export class IpReputationStore {
  private static instance: IpReputationStore | null = null;
  private logger: Logger;
  private records: Map<string, IpReputationRecord> = new Map();
  private storageAdapter: StorageAdapter | null = null;
  private isSaving = false;
  private saveAgain = false;
  // Resolves when the in-flight write (and any chained saveAgain write)
  // finishes - lets shutdown await the final save instead of racing it
  // against storageAdapter.close().
  private savePromise: Promise<void> = Promise.resolve();

  private constructor() {
    this.logger = Logger.getInstance();
  }

  static getInstance(): IpReputationStore {
    if (!IpReputationStore.instance) IpReputationStore.instance = new IpReputationStore();
    return IpReputationStore.instance;
  }

  // Read-only, synchronous, in-memory - safe on the hot connection path.
  // Deliberately only reflects PRIOR history (callers must read this
  // BEFORE calling recordObservation for the current check), so an IP
  // can never bump its own reputation score using the very check that's
  // currently in flight.
  getReputationScore(ip: string): IpReputationScoreResult {
    const record = this.records.get(ip) || null;
    if (!record || record.times_seen < 2) {
      // A brand-new or once-seen IP has no meaningful history either way.
      return { bad: false, good: false, significant: false, score: 0, record };
    }
    const banRatio = record.times_banned / record.times_seen;
    const vpnRatio = record.times_vpn_detected / record.times_seen;
    const avgRisk = record.risk_count > 0 ? record.risk_sum / record.risk_count : 0;
    const score = Math.min(100, Math.round(banRatio * 60 + vpnRatio * 25 + (avgRisk / 100) * 15));
    return {
      bad: score >= 40,
      good: score === 0 && record.times_seen >= 3,
      significant: true,
      score,
      record,
    };
  }

  recordObservation(ip: string, opts: { banned: boolean; vpnDetection: boolean; riskScore: number }): void {
    let record = this.records.get(ip);
    const now = new Date().toISOString();
    if (!record) {
      if (this.records.size >= MAX_RECORDS) this.evictOldest();
      record = { ip, times_seen: 0, times_banned: 0, times_vpn_detected: 0, risk_sum: 0, risk_count: 0, first_seen: now, last_seen: now };
      this.records.set(ip, record);
    }
    record.times_seen++;
    if (opts.banned) record.times_banned++;
    if (opts.vpnDetection) record.times_vpn_detected++;
    if (typeof opts.riskScore === 'number' && !isNaN(opts.riskScore)) {
      record.risk_sum += opts.riskScore;
      record.risk_count++;
    }
    record.last_seen = now;

    // Same "occasional, debounced write" pattern as CacheService - avoid a
    // disk write on every single connection while still persisting
    // reasonably often.
    if (Math.random() < 0.05) this.save();
  }

  getStats() {
    return { ips_tracked: this.records.size };
  }

  private evictOldest(): void {
    // Drop the 10% least-recently-seen records rather than growing
    // unbounded on a very long-running server.
    const entries = Array.from(this.records.values()).sort((a, b) => a.last_seen.localeCompare(b.last_seen));
    const toRemove = Math.max(1, Math.floor(entries.length * 0.1));
    for (let i = 0; i < toRemove; i++) this.records.delete(entries[i].ip);
  }

  // Load records via the configured storage backend (file/sqlite/mysql -
  // see StorageAdapter.ts). Called once at bot startup.
  async initStorage(adapter: StorageAdapter): Promise<void> {
    this.storageAdapter = adapter;
    try {
      const data = await adapter.read('ip_reputation') as Record<string, IpReputationRecord> | null;
      if (data) {
        for (const [ip, record] of Object.entries(data)) this.records.set(ip, record);
        this.logger.info(`IpReputationStore loaded: ${this.records.size} IPs`);
      }
    } catch {
      this.logger.warn('Failed to load ip_reputation store, starting empty');
    }
  }

  // Fire-and-forget for hot-path callers, but returns a promise that
  // resolves once the write (and any chained saveAgain write) actually
  // lands, so shutdown can await the final save.
  save(): Promise<void> {
    if (this.isSaving) { this.saveAgain = true; return this.savePromise; }
    if (!this.storageAdapter) return Promise.resolve(); // not initialized yet
    const data: Record<string, IpReputationRecord> = {};
    this.records.forEach((v, k) => { data[k] = v; });
    this.isSaving = true;
    this.savePromise = this.storageAdapter.write('ip_reputation', data)
      .then(() => {
        this.isSaving = false;
        if (this.saveAgain) { this.saveAgain = false; return this.save(); }
      })
      .catch((e) => {
        this.isSaving = false;
        this.logger.error('Failed to save ip_reputation store', e);
        if (this.saveAgain) { this.saveAgain = false; return this.save(); }
      });
    return this.savePromise;
  }
}
