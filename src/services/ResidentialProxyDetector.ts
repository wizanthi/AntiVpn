// src/services/ResidentialProxyDetector.ts
//
// Dedicated residential-proxy detection - requirement #10.
//
// Residential proxies are the hardest category to catch reliably: by
// design, the traffic exits through a real consumer/mobile IP, so none of
// the "is this a datacenter/hosting network" signals apply. Instead this
// module combines several independent, individually-weak signals and only
// raises its confidence when enough of them agree - never off a single
// signal (min_independent_signals, default 2), consistent with every other
// detector in this project since the v5.0 false-positive audit.
//
// Signals considered (see evaluate() below), each contributing its own
// configurable weight only if it fires:
//   1. A dedicated residential-proxy detection API, if the operator has
//      configured one (RESIDENTIALPROXY_API_KEY / RESIDENTIALPROXY_API_URL)
//      - entirely optional, gated exactly like the other optional
//        key-gated sources in IpChecker.ts (checkVpnApi, checkIPQuality...).
//   2. Network type: a real VPN/proxy-detection API already flagged this
//      connection as VPN/proxy (vpnScore/proxyScore > 0) even though the
//      network itself is NOT a known hosting/datacenter ASN - that
//      combination (proxy traffic riding a non-hosting network) is close
//      to the definition of a residential proxy.
//   3. ASN/organization matches a known residential-proxy resale brand.
//   4. Organization string matches a residential-proxy-resale naming
//      pattern.
//   5. Historical IP reputation (this exact IP has a bad track record).
//   6. CIDR/subnet reputation (this IP's /24 or /48 has a bad track
//      record).
//   7. Suspicious reverse-DNS hostname.
//   8. The existing per-server ML model's confidence score.
//
// The result is cached per IP (cache_ttl_minutes) since none of these
// signals change on a sub-minute basis, and every contributing reason is
// returned so IpChecker/RiskScoringEngine can log exactly why a score was
// assigned (requirement #8).
import axios, { AxiosInstance } from 'axios';
import { Logger } from '../utils/Logger';
import { MemoryCache } from '../utils/MemoryCache';
import { ResidentialProxyConfig, ScoreBreakdownEntry } from '../types';
import { sharedKeepAliveHttpAgent, sharedKeepAliveHttpsAgent } from '../utils/HttpAgents';
import {
  RESIDENTIAL_PROXY_PROVIDERS_NORMALIZED,
  RESIDENTIAL_PROXY_ORG_HINTS_NORMALIZED,
} from './ProviderLists';

export interface ResidentialProxyContext {
  ip: string;
  isp: string;
  org: string;
  asn: number | null;
  hostingScore: number;
  vpnScore: number;
  proxyScore: number;
  reverseDnsSuspicious: boolean;
  cidrReputationBad: boolean;
  ipReputationBad: boolean;
  mlScore: number; // 0-100, from MlDetector.predict()
}

export interface ResidentialProxyResult {
  score: number; // 0-100
  confirmed: boolean;
  reasons: ScoreBreakdownEntry[];
  independentSignals: number;
}

const DEFAULT_CONFIG: ResidentialProxyConfig = {
  enabled: true,
  confidence_threshold: 70,
  cache_ttl_minutes: 360,
  weights: {
    api_signal: 25,
    network_type: 20,
    asn_reputation: 15,
    org_reputation: 10,
    historical_ip_reputation: 12,
    cidr_reputation: 15,
    reverse_dns: 10,
    ml_confidence: 15,
  },
  min_independent_signals: 2,
};

export class ResidentialProxyDetector {
  private static instance: ResidentialProxyDetector | null = null;
  private logger: Logger;
  private config: ResidentialProxyConfig;
  private cache: MemoryCache<ResidentialProxyResult>;
  private httpClient: AxiosInstance;
  private inFlight: Map<string, Promise<ResidentialProxyResult>> = new Map();

  private constructor(config: ResidentialProxyConfig) {
    this.logger = Logger.getInstance();
    this.config = config;
    this.cache = new MemoryCache<ResidentialProxyResult>(config.cache_ttl_minutes * 60 * 1000);
    this.httpClient = axios.create({
      timeout: 2500,
      httpAgent: sharedKeepAliveHttpAgent,
      httpsAgent: sharedKeepAliveHttpsAgent,
      headers: { 'User-Agent': 'WizanthiAntiVpn/ResidentialProxyDetector', 'Accept': 'application/json' },
    });
  }

  static getInstance(config?: ResidentialProxyConfig): ResidentialProxyDetector {
    if (!ResidentialProxyDetector.instance) {
      ResidentialProxyDetector.instance = new ResidentialProxyDetector(config || DEFAULT_CONFIG);
    } else if (config) {
      ResidentialProxyDetector.instance.config = config;
    }
    return ResidentialProxyDetector.instance;
  }

  async evaluate(ctx: ResidentialProxyContext): Promise<ResidentialProxyResult> {
    if (!this.config.enabled) {
      return { score: 0, confirmed: false, reasons: [], independentSignals: 0 };
    }

    const cached = this.cache.get(ctx.ip);
    if (cached) return cached;

    const pending = this.inFlight.get(ctx.ip);
    if (pending) return pending;

    const promise = this.performEvaluation(ctx).finally(() => this.inFlight.delete(ctx.ip));
    this.inFlight.set(ctx.ip, promise);
    return promise;
  }

  private async performEvaluation(ctx: ResidentialProxyContext): Promise<ResidentialProxyResult> {
    const reasons: ScoreBreakdownEntry[] = [];
    const w = this.config.weights;

    // Signal 1: dedicated residential-proxy API (optional, env-gated).
    const apiHit = await this.checkResidentialProxyApi(ctx.ip);
    if (apiHit) reasons.push({ label: 'Residential proxy API', weight: w.api_signal });

    // Signal 2: proxy/VPN-flagged traffic on a non-hosting network - the
    // hallmark of a residential proxy (real consumer IP carrying rented
    // proxy traffic).
    if (ctx.hostingScore === 0 && (ctx.vpnScore > 0 || ctx.proxyScore > 0)) {
      reasons.push({ label: 'Known residential ASN reputation', weight: w.network_type });
    }

    // Signal 3: known residential-proxy resale brand in ISP/org string.
    const combined = `${ctx.isp} ${ctx.org}`.toLowerCase();
    if (RESIDENTIAL_PROXY_PROVIDERS_NORMALIZED.some((k) => combined.includes(k))) {
      reasons.push({ label: 'Known residential proxy provider', weight: w.asn_reputation });
    }

    // Signal 4: org-naming pattern typical of residential-proxy resale.
    if (RESIDENTIAL_PROXY_ORG_HINTS_NORMALIZED.some((k) => combined.includes(k))) {
      reasons.push({ label: 'Organization reputation', weight: w.org_reputation });
    }

    // Signal 5: historical IP reputation.
    if (ctx.ipReputationBad) reasons.push({ label: 'Historical IP reputation', weight: w.historical_ip_reputation });

    // Signal 6: CIDR/subnet reputation.
    if (ctx.cidrReputationBad) reasons.push({ label: 'CIDR reputation', weight: w.cidr_reputation });

    // Signal 7: suspicious reverse DNS.
    if (ctx.reverseDnsSuspicious) reasons.push({ label: 'Reverse DNS', weight: w.reverse_dns });

    // Signal 8: existing ML model confidence (only counts as a signal once
    // reasonably confident, not on any nonzero score).
    if (ctx.mlScore >= 60) reasons.push({ label: 'Existing ML confidence', weight: w.ml_confidence });

    const independentSignals = reasons.length;
    const rawScore = reasons.reduce((s, r) => s + r.weight, 0);
    const score = Math.min(100, rawScore);
    // Never classify as a residential proxy off a single signal, no matter
    // how high its individual weight is (requirement #10).
    const confirmed = independentSignals >= this.config.min_independent_signals && score >= this.config.confidence_threshold;

    if (independentSignals > 0) {
      const line = reasons.map((r) => `+${r.weight} ${r.label}`).join(' ');
      this.logger.debug(`Residential Proxy Score: ${score} | Reasons: ${line} =${score}`);
    }

    const result: ResidentialProxyResult = { score, confirmed, reasons, independentSignals };
    this.cache.set(ctx.ip, result);
    return result;
  }

  // Optional pluggable residential-proxy detection API. No-ops (returns
  // false) unless both env vars are configured, mirroring the pattern
  // IpChecker.ts already uses for VPNAPI_KEY/IPQUALITY_KEY/etc. Kept
  // generic (a base URL + `?ip=` + `&key=`) rather than hardcoding one
  // vendor, since "if configured" implies the operator brings their own.
  private async checkResidentialProxyApi(ip: string): Promise<boolean> {
    try {
      const key = process.env.RESIDENTIALPROXY_API_KEY;
      const baseUrl = process.env.RESIDENTIALPROXY_API_URL;
      if (!key || !baseUrl) return false;
      const separator = baseUrl.includes('?') ? '&' : '?';
      const r = await this.httpClient.get(`${baseUrl}${separator}ip=${ip}&key=${key}`);
      const d = r.data || {};
      return !!(d.is_residential_proxy || d.residential_proxy || d.proxy_type === 'residential');
    } catch {
      return false;
    }
  }

  getStats() {
    return { cache_size: this.cache.size };
  }
}
