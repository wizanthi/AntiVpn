// src/services/NetworkAgeService.ts
//
// Network age / WHOIS lookup - requirement #3.
//
// Determines, on a best-effort basis, how long ago the ASN (or, failing
// that, the specific IP's network) was registered, using RDAP - the
// modern, structured, authoritative successor to WHOIS that IpChecker
// already relies on elsewhere (see checkRdap in IpChecker.ts) - rather than
// screen-scraping legacy WHOIS text. A recently-allocated hosting range is
// a weak-but-real signal (freshly spun-up VPN/proxy infrastructure), so
// this only ever nudges the score slightly (see
// DetectionDefaults.weights - there is no dedicated "network age" weight
// in the top-level scoring table; instead it folds into the existing
// "Hosting ASN" signal context via the risk-assessment log line, and
// separately informs ResidentialProxyDetector). It NEVER fails hard: any
// error, timeout, or missing data simply results in a null age, which
// every caller treats as "no signal", not "suspicious".
//
// Cached aggressively (default 7 days) and keyed by ASN where possible,
// since a network's allocation date is effectively immutable - this is the
// single most cacheable lookup in the whole detection pipeline and the one
// most worth protecting from repeated WHOIS/RDAP traffic.
import axios, { AxiosInstance } from 'axios';
import { Logger } from '../utils/Logger';
import { MemoryCache } from '../utils/MemoryCache';
import { NetworkAgeConfig } from '../types';
import { sharedKeepAliveHttpAgent, sharedKeepAliveHttpsAgent } from '../utils/HttpAgents';

export interface NetworkAgeResult {
  asn: number | null;
  allocationDate: string | null;
  ageDays: number | null;
  isRecent: boolean;
}

const DEFAULT_CONFIG: NetworkAgeConfig = {
  enabled: true,
  young_network_days: 180,
  cache_ttl_hours: 168,
  timeout_ms: 2500,
};

export class NetworkAgeService {
  private static instance: NetworkAgeService | null = null;
  private logger: Logger;
  private cache: MemoryCache<NetworkAgeResult>;
  private config: NetworkAgeConfig;
  private httpClient: AxiosInstance;
  private inFlight: Map<string, Promise<NetworkAgeResult>> = new Map();

  private constructor(config: NetworkAgeConfig) {
    this.logger = Logger.getInstance();
    this.config = config;
    this.cache = new MemoryCache<NetworkAgeResult>(config.cache_ttl_hours * 60 * 60 * 1000);
    this.httpClient = axios.create({
      timeout: config.timeout_ms,
      httpAgent: sharedKeepAliveHttpAgent,
      httpsAgent: sharedKeepAliveHttpsAgent,
      headers: { 'User-Agent': 'WizanthiAntiVpn/NetworkAgeService', 'Accept': 'application/json' },
      maxContentLength: 10 * 1024 * 1024,
      maxBodyLength: 10 * 1024 * 1024,
    });
  }

  static getInstance(config?: NetworkAgeConfig): NetworkAgeService {
    if (!NetworkAgeService.instance) {
      NetworkAgeService.instance = new NetworkAgeService(config || DEFAULT_CONFIG);
    } else if (config) {
      NetworkAgeService.instance.config = config;
      NetworkAgeService.instance.httpClient.defaults.timeout = config.timeout_ms;
    }
    return NetworkAgeService.instance;
  }

  // `asn` should come from AsnIndex's already-resolved lookup where
  // available (no extra network round trip needed to learn it); falls back
  // to an RDAP IP lookup keyed by the raw IP when the ASN is unknown.
  async getNetworkAge(ip: string, asn: number | null): Promise<NetworkAgeResult> {
    if (!this.config.enabled) {
      return { asn, allocationDate: null, ageDays: null, isRecent: false };
    }

    const cacheKey = asn ? `asn:${asn}` : `ip:${ip}`;
    const cached = this.cache.get(cacheKey);
    if (cached) return cached;

    const pending = this.inFlight.get(cacheKey);
    if (pending) return pending;

    const promise = this.performLookup(ip, asn, cacheKey).finally(() => this.inFlight.delete(cacheKey));
    this.inFlight.set(cacheKey, promise);
    return promise;
  }

  private async performLookup(ip: string, asn: number | null, cacheKey: string): Promise<NetworkAgeResult> {
    let result: NetworkAgeResult;
    try {
      const url = asn ? `https://rdap.org/autnum/${asn}` : `https://rdap.org/ip/${ip}`;
      const r = await this.httpClient.get(url);
      const events: any[] = Array.isArray(r.data?.events) ? r.data.events : [];
      const registration = events.find((e) => e?.eventAction === 'registration') || events[0];
      const dateStr: string | null = registration?.eventDate || null;

      let ageDays: number | null = null;
      if (dateStr) {
        const parsed = new Date(dateStr).getTime();
        if (!isNaN(parsed)) ageDays = Math.max(0, Math.floor((Date.now() - parsed) / (1000 * 60 * 60 * 24)));
      }

      result = {
        asn,
        allocationDate: dateStr,
        ageDays,
        isRecent: ageDays !== null && ageDays < this.config.young_network_days,
      };
    } catch {
      // WHOIS/RDAP unavailable, rate-limited, or the record has no usable
      // date - never treat this as suspicious, just "unknown".
      result = { asn, allocationDate: null, ageDays: null, isRecent: false };
    }
    this.cache.set(cacheKey, result);
    return result;
  }

  getStats() {
    return { cache_size: this.cache.size };
  }
}
