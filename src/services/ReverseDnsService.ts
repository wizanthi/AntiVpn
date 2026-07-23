// src/services/ReverseDnsService.ts
//
// Dedicated reverse-DNS (PTR) detection - requirement #2.
//
// IpChecker already performs a reverse-DNS lookup as one of its Layer 1
// API-battery entries (checkReverseDNS), feeding a narrow keyword set into
// the existing vpnScore/vpnSources corroboration count. This service is the
// single source of truth for that lookup (checkReverseDNS now delegates
// here - see IpChecker.ts) and additionally exposes the broader keyword set
// requested in the brief (vpn, proxy, colo, hosting, cloud, vps, server,
// exit, tor) as its own "suspicious" signal for the weighted scoring
// engine. It is NEVER used as a standalone ban reason - see requirement #9
// and RiskScoringEngine's multi-signal requirement.
//
// Every lookup is cached (in-memory, TTL-based) and de-duplicated against
// concurrent in-flight requests for the same IP, so a burst of connections
// sharing an IP/subnet never triggers redundant DNS traffic.
import * as dns from 'dns';
import { promisify } from 'util';
import { Logger } from '../utils/Logger';
import { MemoryCache } from '../utils/MemoryCache';
import { ReverseDnsConfig } from '../types';

const dnsReverse = promisify(dns.reverse);

export interface ReverseDnsResult {
  ip: string;
  hostname: string | null;
  suspicious: boolean;
  matchedKeyword: string | null;
}

const DEFAULT_CONFIG: ReverseDnsConfig = {
  enabled: true,
  keywords: ['vpn', 'proxy', 'colo', 'hosting', 'cloud', 'vps', 'server', 'exit', 'tor'],
  cache_ttl_minutes: 720,
  timeout_ms: 2000,
};

export class ReverseDnsService {
  private static instance: ReverseDnsService | null = null;
  private logger: Logger;
  private cache: MemoryCache<ReverseDnsResult>;
  private config: ReverseDnsConfig;
  private inFlight: Map<string, Promise<ReverseDnsResult>> = new Map();

  private constructor(config: ReverseDnsConfig) {
    this.logger = Logger.getInstance();
    this.config = config;
    this.cache = new MemoryCache<ReverseDnsResult>(config.cache_ttl_minutes * 60 * 1000);
  }

  static getInstance(config?: ReverseDnsConfig): ReverseDnsService {
    if (!ReverseDnsService.instance) {
      ReverseDnsService.instance = new ReverseDnsService(config || DEFAULT_CONFIG);
    } else if (config) {
      ReverseDnsService.instance.reconfigure(config);
    }
    return ReverseDnsService.instance;
  }

  reconfigure(config: ReverseDnsConfig): void {
    this.config = config;
    // A new TTL only applies to entries cached from this point forward;
    // existing entries keep their original expiry, which is fine since
    // this only ever runs once at startup in practice.
  }

  async lookup(ip: string): Promise<ReverseDnsResult> {
    if (!this.config.enabled) {
      return { ip, hostname: null, suspicious: false, matchedKeyword: null };
    }

    const cached = this.cache.get(ip);
    if (cached) return cached;

    const pending = this.inFlight.get(ip);
    if (pending) return pending;

    const promise = this.performLookup(ip).finally(() => this.inFlight.delete(ip));
    this.inFlight.set(ip, promise);
    return promise;
  }

  private async performLookup(ip: string): Promise<ReverseDnsResult> {
    let result: ReverseDnsResult;
    try {
      const hostnames = await this.withTimeout(dnsReverse(ip), this.config.timeout_ms);
      const hostname = hostnames?.[0] || null;
      const lower = (hostname || '').toLowerCase();
      const matched = this.config.keywords.find((k) => lower.includes(k)) || null;
      result = { ip, hostname, suspicious: !!matched, matchedKeyword: matched };
    } catch {
      // No PTR record, resolver timeout/failure, etc. - absence of a
      // hostname is NOT itself suspicious (plenty of legitimate
      // residential connections have no PTR record at all).
      result = { ip, hostname: null, suspicious: false, matchedKeyword: null };
    }
    this.cache.set(ip, result);
    return result;
  }

  private withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('reverse-dns timeout')), ms);
      p.then((v) => { clearTimeout(timer); resolve(v); }, (e) => { clearTimeout(timer); reject(e); });
    });
  }

  getStats() {
    return { cache_size: this.cache.size };
  }
}
