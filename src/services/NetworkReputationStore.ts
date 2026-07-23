// src/services/NetworkReputationStore.ts
//
// Subnet (CIDR) reputation tracking - requirement #1.
//
// Tracks, per /24 IPv4 network and per /48 IPv6 network:
//   - how many distinct IPs in that subnet have been banned
//   - how many distinct IPs have triggered a VPN/proxy/hosting/tor
//     detection
//   - how many distinct IPs have been observed at all ("unique players", as
//     a proxy for unique connecting clients - this project doesn't have a
//     stable player identity independent of IP)
//   - a running average risk score for the subnet
//
// IMPORTANT SAFETY PROPERTY: this store only ever produces a *score*
// (getReputationScore) that IpChecker/RiskScoringEngine folds in as ONE
// weighted signal among several. Nothing in this file ever returns a
// standalone "ban" verdict, and callers are expected (see IpChecker) to
// never treat a subnet-reputation hit as sufficient on its own - see
// requirement #2 "Never ban based only on subnet reputation" and
// requirement #9's false-positive guards.
//
// Storage: this project has no database layer, only small JSON files
// managed by singletons that hold everything in memory and persist with
// debounced, fire-and-forget writes (see ListManager/CacheService). This
// store follows the exact same pattern so it fits the existing
// architecture rather than introducing a new persistence mechanism.
import { NetworkReputationRecord } from '../types';
import { Logger } from '../utils/Logger';
import { StorageAdapter } from './StorageAdapter';

interface ReputationScoreResult {
  bad: boolean;       // subnet looks disproportionately abusive
  significant: boolean; // enough samples for the score to mean anything
  score: number;       // 0-100 "badness" fraction of the subnet
  record: NetworkReputationRecord | null;
}

export class NetworkReputationStore {
  private static instance: NetworkReputationStore | null = null;
  private logger: Logger;
  private records: Map<string, NetworkReputationRecord> = new Map();
  // Bounded per-subnet set of IPs already counted toward unique_ips, so a
  // player reconnecting with the same IP repeatedly doesn't inflate the
  // subnet's sample count. Capped per-subnet to avoid unbounded memory use
  // on a very large/abused subnet - once capped, further truly-new IPs are
  // still reflected approximately via the persisted unique_ips counter.
  private seenIpsBySubnet: Map<string, Set<string>> = new Map();
  private readonly maxTrackedIpsPerSubnet = 4096;
  private storageAdapter: StorageAdapter | null = null;
  private ipv4Prefix: number = 24;
  private ipv6Prefix: number = 48;
  private minSamplesForScore: number = 5;

  private isSaving = false;
  private saveAgain = false;
  // Resolves when the in-flight write (and any chained saveAgain write)
  // finishes - lets shutdown await the final save instead of racing it
  // against storageAdapter.close().
  private savePromise: Promise<void> = Promise.resolve();
  private dirtyCount = 0;

  private constructor() {
    this.logger = Logger.getInstance();
  }

  static getInstance(): NetworkReputationStore {
    if (!NetworkReputationStore.instance) NetworkReputationStore.instance = new NetworkReputationStore();
    return NetworkReputationStore.instance;
  }

  // Called once at startup (see IpChecker.initialize) with the operator's
  // configured prefixes/thresholds - kept out of the constructor since
  // config isn't available yet when the singleton is first touched.
  configure(opts: { ipv4Prefix: number; ipv6Prefix: number; minSamplesForScore: number }): void {
    this.ipv4Prefix = opts.ipv4Prefix;
    this.ipv6Prefix = opts.ipv6Prefix;
    this.minSamplesForScore = opts.minSamplesForScore;
  }

  // Fold in one observation for the IP's subnet. Cheap (in-memory Map
  // update); disk persistence is debounced/probabilistic, same pattern as
  // CacheService, so this never blocks the connection it's called from.
  recordObservation(ip: string, opts: { banned: boolean; vpnDetection: boolean; riskScore: number }): void {
    const subnet = this.subnetKeyForIp(ip);
    if (!subnet) return; // unparseable IP - nothing to key on

    let record = this.records.get(subnet);
    const now = new Date().toISOString();
    if (!record) {
      record = { subnet, banned_ips: 0, vpn_detections: 0, unique_ips: 0, risk_sum: 0, risk_count: 0, first_seen: now, last_updated: now };
      this.records.set(subnet, record);
    }

    let seen = this.seenIpsBySubnet.get(subnet);
    if (!seen) { seen = new Set(); this.seenIpsBySubnet.set(subnet, seen); }
    const isNewIp = !seen.has(ip);
    if (isNewIp) {
      if (seen.size < this.maxTrackedIpsPerSubnet) seen.add(ip);
      record.unique_ips++;
    }

    if (opts.banned) record.banned_ips++;
    if (opts.vpnDetection) record.vpn_detections++;
    if (typeof opts.riskScore === 'number' && !isNaN(opts.riskScore)) {
      record.risk_sum += opts.riskScore;
      record.risk_count++;
    }
    record.last_updated = now;

    this.dirtyCount++;
    // Debounced, low-frequency persistence: subnet-level writes are far
    // less frequent than per-connection cache writes already (one write
    // path shared across every IP in the /24 or /48), so a fixed cadence
    // of "every 20 updates" keeps data/network_reputation.json reasonably
    // fresh without a disk write on every single player connection.
    if (this.dirtyCount >= 20) {
      this.dirtyCount = 0;
      this.save();
    }
  }

  // Read-only, synchronous, zero I/O - safe to call on every connection.
  getReputationScore(ip: string): ReputationScoreResult {
    const subnet = this.subnetKeyForIp(ip);
    if (!subnet) return { bad: false, significant: false, score: 0, record: null };
    const record = this.records.get(subnet) || null;
    if (!record || record.unique_ips < this.minSamplesForScore) {
      return { bad: false, significant: false, score: 0, record };
    }

    const bannedRatio = record.banned_ips / record.unique_ips;
    const vpnRatio = record.vpn_detections / record.unique_ips;
    const avgRisk = record.risk_count > 0 ? record.risk_sum / record.risk_count : 0;

    // Blend three independent views of "how bad is this subnet" into one
    // 0-100 score: what fraction of it has been banned, what fraction
    // tripped a VPN/proxy detection, and its average historical risk.
    const score = Math.min(100, Math.round((bannedRatio * 60 + vpnRatio * 25 + (avgRisk / 100) * 15)));
    return { bad: score >= 40, significant: true, score, record };
  }

  getReputation(ip: string): NetworkReputationRecord | null {
    const subnet = this.subnetKeyForIp(ip);
    if (!subnet) return null;
    return this.records.get(subnet) || null;
  }

  getStats() {
    return { subnets_tracked: this.records.size };
  }

  // --- Subnet key derivation ---------------------------------------------
  subnetKeyForIp(ip: string): string | null {
    if (ip.includes(':')) return this.ipv6SubnetKey(ip);
    return this.ipv4SubnetKey(ip);
  }

  private ipv4SubnetKey(ip: string): string | null {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return null;
    const bits = this.ipv4Prefix;
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    const num = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
    const base = (num & mask) >>> 0;
    const o = [(base >>> 24) & 255, (base >>> 16) & 255, (base >>> 8) & 255, base & 255];
    return `${o.join('.')}/${bits}`;
  }

  // Simplified IPv6 /48 (or configured prefix) grouping: only whole-hextet
  // prefixes are supported (multiples of 16 bits), which covers the
  // default /48 case exactly and keeps this dependency-free (no extra
  // "ip" npm package needed just for address math).
  private ipv6SubnetKey(ip: string): string | null {
    const bits = this.ipv6Prefix;
    const hextetCount = Math.max(1, Math.round(bits / 16));
    const expanded = this.expandIpv6(ip);
    if (!expanded) return null;
    const prefixHextets = expanded.slice(0, hextetCount);
    return `${prefixHextets.join(':')}::/${hextetCount * 16}`;
  }

  // Expands "::" shorthand into a full 8-hextet array. Returns null on
  // anything that doesn't look like a valid IPv6 address rather than
  // throwing - callers treat null as "skip subnet reputation for this IP".
  private expandIpv6(ip: string): string[] | null {
    const clean = ip.split('%')[0]; // strip zone index if present
    if (!clean.includes(':')) return null;
    const parts = clean.split('::');
    if (parts.length > 2) return null;

    const head = parts[0] ? parts[0].split(':').filter(Boolean) : [];
    const tail = parts.length === 2 && parts[1] ? parts[1].split(':').filter(Boolean) : [];
    if (parts.length === 1) {
      // No "::" - must be exactly 8 groups.
      const groups = clean.split(':');
      if (groups.length !== 8) return null;
      return groups.map((g) => g.padStart(4, '0'));
    }
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    const zeros = new Array(missing).fill('0000');
    return [...head, ...zeros, ...tail].map((g) => g.padStart(4, '0'));
  }

  // --- Persistence (same debounced fire-and-forget pattern as
  // ListManager/CacheService, via the configured storage backend) --------
  // Load records via the configured storage backend (file/sqlite/mysql -
  // see StorageAdapter.ts). Called once at bot startup.
  async initStorage(adapter: StorageAdapter): Promise<void> {
    this.storageAdapter = adapter;
    try {
      const data = await adapter.read('network_reputation') as Record<string, NetworkReputationRecord> | null;
      if (data) {
        for (const [subnet, record] of Object.entries(data)) this.records.set(subnet, record);
        this.logger.info(`NetworkReputationStore loaded: ${this.records.size} subnets`);
      }
    } catch (e) {
      this.logger.warn('Failed to load network_reputation store, starting empty');
    }
  }

  // Fire-and-forget for hot-path callers, but returns a promise that
  // resolves once the write (and any chained saveAgain write) actually
  // lands, so shutdown can await the final save.
  save(): Promise<void> {
    if (this.isSaving) { this.saveAgain = true; return this.savePromise; }
    if (!this.storageAdapter) return Promise.resolve(); // not initialized yet
    const data: Record<string, NetworkReputationRecord> = {};
    this.records.forEach((v, k) => { data[k] = v; });
    this.isSaving = true;
    this.savePromise = this.storageAdapter.write('network_reputation', data)
      .then(() => {
        this.isSaving = false;
        if (this.saveAgain) { this.saveAgain = false; return this.save(); }
      })
      .catch((e) => {
        this.isSaving = false;
        this.logger.error('Failed to save network_reputation store', e);
        if (this.saveAgain) { this.saveAgain = false; return this.save(); }
      });
    return this.savePromise;
  }
}
