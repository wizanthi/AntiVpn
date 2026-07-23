// src/services/IpChecker.ts
//
// v8.0 — adds the weighted reputation-scoring engine (RiskScoringEngine),
// CIDR/subnet reputation (NetworkReputationStore), per-IP historical
// reputation (IpReputationStore), a dedicated cached reverse-DNS detector
// (ReverseDnsService), best-effort network-age/WHOIS lookup
// (NetworkAgeService), and a dedicated residential-proxy detector
// (ResidentialProxyDetector). All of it is strictly additive: every ban
// path that existed in v7.0 (ASN-index, ASN-cache, API-threshold, keyword,
// ML) is untouched and still requires exactly what it required before. The
// new signals only do two things — (1) enrich every IpCheckResult with a
// transparent, logged score breakdown for debugging, and (2) back one new
// terminal path (Layer 3.75, "weighted composite") that a connection can
// only reach after every one of the layers above it has already found
// nothing, and which itself refuses to fire unless several independent
// weighted categories agree (see detection.min_independent_signals_for_ban
// in config.json) — see requirement #9 in the project brief.
//
// v7.0 — faster and more complete detection, no accuracy trade-off.
//
// ADDED vs v6.0:
//   - Local, offline IP->ASN index (AsnIndex.ts): the live api.iptoasn.com
//     call per-connection is gone, replaced by a bulk-downloaded,
//     periodically-refreshed table held in memory and looked up with
//     binary search - zero network latency, zero dependency on that API
//     being up. A hit against VERIFIED_HOSTING_VPN_ASNS (now expanded)
//     bans instantly, before any of the 12 remaining network calls fire.
//   - ASN-verdict cache: once an ASN is corroborated as hosting/datacenter
//     through the full API battery, any other IP seen in that same ASN
//     gets an instant local verdict for the next few hours instead of
//     repeating the whole round - closing the gap where a provider
//     rotates in new IPs faster than the 6-hourly bulk list refresh.
//   - Early-exit scoring: API results are folded into the running verdict
//     as they land, and the moment a ban threshold is already met the
//     function stops waiting on whichever slow source(s) are still
//     in-flight. A clean verdict still waits for everything, since a
//     partial "no signal yet" never proves innocence - so recall/FP rate
//     for legitimate players is unaffected; only the ban path got faster.
//   - Keep-alive HTTP/HTTPS agents so the many small per-check requests
//     reuse TCP+TLS connections instead of renegotiating every time, and a
//     tighter 2.5s per-call timeout (from 3.5s).
//   - getipintel.net added as another optional, free (contact-email,
//     no key) purpose-built VPN/proxy probability source, gated behind
//     GETIPINTEL_EMAIL like the other optional API-key sources already in
//     this file - pure additional corroboration, same 2-source bar.
//   - VERIFIED_HOSTING_VPN_ASNS (ProviderLists.ts) expanded with more
//     individually-confirmed pure-hosting ASNs (Scaleway, Contabo,
//     LeaseWeb NL, Alibaba Cloud, Tencent Cloud, UpCloud, ColoCrossing,
//     ReliableSite, FranTech/BuyVM), and ListUpdater's bulk static list now
//     also pulls the official AWS/GCP/Oracle published IP-range documents
//     directly - zero false-positive risk, since those documents are the
//     providers' own network space, not a guess.
//
// v6.0 — adds more real, verifiable signals and removes a per-request
// latency cost, while keeping every false-positive guard from the v5.0
// audit intact (trusted-provider whitelist, multi-source corroboration,
// brand-name-only keyword lists).
//
// ADDED vs v5.0 (each one is a real, independently-checkable technical fact
// or purpose-built detection service — not a guess):
//   - Live ASN lookup (api.iptoasn.com, no key) cross-referenced against
//     VERIFIED_HOSTING_VPN_ASNS — the *same* ASN numbers this project
//     already individually confirmed for ListUpdater's bulk per-ASN prefix
//     download. This catches newly-assigned IPs inside those networks
//     before the next 6-hourly bulk refresh, using a technical fact (which
//     network announces the IP's BGP prefix) rather than a name guess.
//     [Superseded in v7.0 by the local AsnIndex - see above.]
//   - RDAP lookup (rdap.org, no key, authoritative registry data) feeds the
//     network/org name through the exact same brand-name keyword lists
//     already used elsewhere, purely as one more independent source for the
//     multi-source corroboration count below.
//   - ipapi.is (no key required for light use) — a purpose-built
//     VPN/proxy/datacenter detection service, same treatment as the other
//     Layer 1 APIs.
//   - Tor Project exit-list membership is now checked from an in-memory
//     cache refreshed on a timer, instead of re-downloading the full
//     torbulkexitlist over HTTP on every single non-cached IP. Same
//     authoritative source, no more per-connection network round trip.
//   - Concurrent-connection dedup: if two players connect with the same IP
//     while a check is already in flight, the second one now waits on the
//     same in-flight promise instead of firing a duplicate round of API
//     calls.
//
// v5.0 — trimmed down after a false-positive audit.
//
// REMOVED vs previous version (and why each one caused false-positive bans):
//   - Hardcoded "suspicious ranges" of whole /16 blocks (65k+ IPs each) with
//     guessed reasons like "VPN/Proxy Range". Banning an entire /16 on a
//     hunch bans every residential/business customer on that ISP.
//   - Active network probes against the PLAYER's IP: port scans (1080, 3128,
//     8080, 9050, 51820, etc.), ping/TTL/ICMP heuristics, "SYN flood" and
//     GRE-tunnel port checks. A home router or PC can have any of these
//     ports open (games, NAS, torrent client, IoT) for reasons that have
//     nothing to do with VPN use, and residential TTL/latency values vary
//     enormously by hop count, not by VPN use.
//   - TLS/JA3/JARM/ALPN "fingerprint" checks that connect to the player's IP
//     on port 443. Ordinary players don't run a TLS server, so the
//     connection fails — and several of these checks treated "connection
//     failed" as *suspicious*, which flags nearly every normal player.
//   - DNS-record heuristics (SOA/CAA/DNSSEC/SPF/DMARC/DKIM/MX/NS/SRV/TXT
//     records on the reverse-DNS zone). These records describe unrelated
//     infrastructure and have no real correlation with VPN/proxy usage.
//   - Malware/abuse threat-intel feeds (VirusTotal, GreyNoise, AlienVault
//     OTX, IBM X-Force, abuse.ch, ThreatFox, Cisco Talos) repurposed as
//     VPN/proxy signals. These flag any IP with a past malicious-activity
//     report — including previously-infected residential IPs later
//     reassigned to an innocent player. Wrong category of "risk" entirely.
//   - Non-existent / mismatched third-party endpoints (ip-intel.xyz,
//     fingerprintjs.com "IP lookup") that were dead weight.
//   - A one-word-generic keyword list ("cloud", "hosting", "proxy",
//     "server", "vps", "iaas"...) matched as a substring against ISP/org
//     name. Plenty of legitimate mobile and business ISPs have words like
//     "cloud" or "server" somewhere in their registered org name.
//
// This is the exact combination that produced a real false-positive ban
// found in this project's own data/blacklist.json: an ordinary Ukrainian
// individual-entrepreneur ISP customer ("PE Yakymenko Mykola
// Oleksandrovych") was banned by the old "Extended" 48-method layer.
//
// KEPT:
//   - Whitelist / private-IP / persistent blacklist / custom-ban instant
//     checks (Layer 0).
//   - Real, purpose-built IP-intelligence APIs that actually detect
//     VPN/proxy/hosting usage, combined with a require-multiple-
//     confirmations threshold (Layer 1).
//   - Trusted-provider whitelist for well-known residential/mobile ISPs
//     (Layer 2) — this runs BEFORE keyword matching so an ISP that happens
//     to contain a matched word never gets banned if it's a known
//     legitimate carrier.
//   - A much shorter, brand-name-only keyword list (Layer 3).
//   - The official Tor Project exit-node list (Layer 4) — this is an
//     authoritative, actively-maintained list, not a guess.

import axios, { AxiosInstance } from 'axios';
import { IpCheckResult, AppConfig, DetectionConfig, ApisConfig } from '../types';
import { CacheService } from '../utils/Cache';
import { Logger } from '../utils/Logger';
import { sharedKeepAliveHttpAgent, sharedKeepAliveHttpsAgent } from '../utils/HttpAgents';
import { ListManager } from './ListManager';
import { CustomBanManager } from './CustomBanManager';
import { AsnIndex } from './AsnIndex';
import { MlDetector } from './MlDetector';
import {
  VERIFIED_HOSTING_VPN_ASNS_SET,
  VPN_KEYWORDS_NORMALIZED,
  PROXY_KEYWORDS_NORMALIZED,
  HOSTING_KEYWORDS_NORMALIZED,
  DATACENTER_KEYWORDS_NORMALIZED,
  TRUSTED_PROVIDERS_NORMALIZED,
} from './ProviderLists';
// --- v8.0 reputation-scoring engine additions (requirements #1-#10) ---
// Each of these is its own dedicated, independently-cached, fail-open
// module - see the file-level comment in each for its exact role. None of
// them can single-handedly ban a player; they only ever feed weighted
// signals into RiskScoringEngine / the multi-source corroboration checks
// already present in this file (see requirement #9).
import { NetworkReputationStore } from './NetworkReputationStore';
import { IpReputationStore } from './IpReputationStore';
import { ReverseDnsService } from './ReverseDnsService';
import { NetworkAgeService } from './NetworkAgeService';
import { ResidentialProxyDetector } from './ResidentialProxyDetector';
import { RiskScoringEngine } from './RiskScoringEngine';
import { DEFAULT_DETECTION_CONFIG } from '../config/DetectionDefaults';
// v8.1 - data/datasets custom IP/ASN/ISP block-list support (requirement:
// "make it support database/dataset of ips or asns or isps") - see
// DatasetLoader.ts for the full format-by-format breakdown.
import { DatasetLoader } from './DatasetLoader';
import { DatasetMatch, DatasetsConfig } from '../types';
import { DEFAULT_DATASETS_CONFIG } from '../config/DatasetsDefaults';
// v8.2 - three new Layer 1 sources (proxycheck.io upgraded to v3, plus
// iplocate.io and ipregistry.co), and three cross-cutting knobs that now
// apply to every Layer 1 API uniformly instead of being hand-rolled per
// service:
//   - IPCHECK_DISABLED_SERVICES: comma-separated service ids
//     (ipapi,ipwhois,ipapico,ipinfo,vpnapi,proxycheck,ipquality,abuseipdb,
//     ipapiis,rdap,getipintel,iplocate,ipregistry) to force-disable any
//     subset, free or keyed - the free ones had no off switch before this.
//   - <SERVICE_ID>_URL (e.g. PROXYCHECK_URL, IPLOCATE_URL): overrides that
//     service's built-in endpoint, with {ip}/{key} placeholders substituted
//     - lets an operator point a service at a mirror/compatible replacement
//     without touching code. Unset = today's hardcoded default, unchanged.
//   - Rate-limit cooldown: a 429 (honoring Retry-After) or a response body
//     matching common quota-exceeded phrasing now marks that service via
//     ApiCooldownTracker, so it's skipped with zero network I/O until the
//     cooldown elapses (IPCHECK_RATE_LIMIT_COOLDOWN_MINUTES, default 60)
//     instead of being retried and failing again on every subsequent
//     connection. See resolveUrl/detectRateLimit/safeGet below.
import { ApiCooldownTracker } from './ApiCooldownTracker';
// v8.3 - the same per-service enable/key knobs above are now also settable
// from config.json's `apis` block (see ApisDefaults.ts / types.ts), so an
// operator doesn't have to touch env vars at all. config.json wins when
// both are set; env vars remain a fallback for existing deployments - see
// resolveApiKey/isServiceEnabled below.
import { DEFAULT_APIS_CONFIG } from '../config/ApisDefaults';

interface ApiSignal {
  country?: string; city?: string; isp?: string; org?: string;
  isVpn?: boolean; vpnWeight?: number;
  isProxy?: boolean; proxyWeight?: number;
  isTor?: boolean; torWeight?: number;
  isHosting?: boolean; hostingWeight?: number;
  isDatacenter?: boolean; datacenterWeight?: number;
  // FP-hardening: a weak signal contributes to the category *score* but is
  // never counted as a confirming *source* and never overwrites isp/org/
  // country/city. Set by derived/inference signals (reverse-DNS hostname
  // substring, RDAP org-name keyword match) - two of those agreeing is NOT
  // two independent detection services agreeing, and letting them count as
  // sources let "dsl-tunnel-gw.isp.net" + one stale API result reach the
  // 2-source permanent-ban bar. Purpose-built APIs leave this unset.
  weak?: boolean;
  // Provenance family for the multi-source corroboration count - two
  // services known to resell the same upstream dataset share a family and
  // together count as ONE source. Defaults to the service's own id (every
  // service is its own family) so detection is unchanged except where
  // sameness is explicitly declared.
  family?: string;
}

interface RunningVerdict {
  country: string; city: string; isp: string; org: string;
  vpnScore: number; proxyScore: number; torScore: number; hostingScore: number; datacenterScore: number;
  vpnSources: number; proxySources: number; torSources: number; hostingSources: number; datacenterSources: number;
  // Distinct provenance families per category (backs the *Sources counts
  // above - see applySignal).
  vpnFamilies: Set<string>; proxyFamilies: Set<string>; torFamilies: Set<string>;
  hostingFamilies: Set<string>; datacenterFamilies: Set<string>;
}

export class IpChecker {
  private static instance: IpChecker | null = null;
  private httpClient: AxiosInstance;
  private cache: CacheService;
  private listManager: ListManager;
  private customBanManager: CustomBanManager;
  private logger: Logger;
  private config: AppConfig | null = null;
  private isInitialized: boolean = false;

  // In-flight dedup: if two players share an IP and connect around the same
  // time, the second check reuses the first's pending promise instead of
  // firing a duplicate round of API calls.
  private inFlight: Map<string, Promise<IpCheckResult>> = new Map();

  // Background-refreshed Tor exit-node cache (see refreshTorExitList below).
  private torExitSet: Set<string> = new Set();
  private torExitLoadedAt: number = 0;
  private torExitRefreshMs: number = 10 * 60 * 1000; // 10 minutes
  private torExitRefreshing: Promise<void> | null = null;

  // Offline IP->ASN table (see AsnIndex.ts) - answers "which network
  // announces this IP" locally, with zero network round trip.
  private asnIndex: AsnIndex;
  private mlDetector: MlDetector = MlDetector.getInstance();

  // Short-TTL cache of confirmed-hosting verdicts keyed by ASN number. Once
  // an ASN has been corroborated as hosting/datacenter infrastructure by
  // the same multi-source bar used everywhere else in this file, any other
  // IP that shows up in that same ASN gets an instant verdict without
  // repeating the full 12-way API round - this catches a VPN/hosting
  // provider's newly-rotated IPs faster than the 6-hourly bulk list
  // refresh, while never lowering the corroboration bar itself (the cached
  // entry only exists because that bar was already cleared once).
  private asnVerdictCache: Map<number, { hosting: boolean; datacenter: boolean; at: number }> = new Map();
  private readonly asnVerdictTtlMs = 6 * 60 * 60 * 1000; // 6h - matches bulk-list refresh cadence

  // --- v8.0 reputation-scoring engine services (see imports above) ---
  private networkReputationStore: NetworkReputationStore;
  private ipReputationStore: IpReputationStore;
  private reverseDnsService: ReverseDnsService;
  private networkAgeService: NetworkAgeService;
  private residentialProxyDetector: ResidentialProxyDetector;
  private riskEngine: RiskScoringEngine;
  private detectionConfig: DetectionConfig = DEFAULT_DETECTION_CONFIG;
  // v8.1 - data/datasets loader (see DatasetLoader.ts). Config is applied
  // in initialize(); the loader itself is a singleton so its indexes
  // survive independently of IpChecker (e.g. if IpChecker were ever
  // reconstructed in a test harness).
  private datasetLoader: DatasetLoader;
  private datasetsConfig: DatasetsConfig = DEFAULT_DATASETS_CONFIG;
  // Uppercased ISO-2 set built from datasets.exclude_countries in
  // initialize() - a player whose IP's ASN-index country is in here is
  // exempt from the DATASET checks only (never dataset-banned, never gets
  // the dataset_match composite signal); every other detection layer still
  // applies to them unchanged. Precomputed once so the per-connection check
  // is a single Set.has().
  private datasetExcludedCountries: Set<string> = new Set();
  // Tracks the in-flight (or already-settled) initial datasets load kicked
  // off in initialize() below, so callers that need it - namely the
  // startup sequence in index.ts, which wants datasets ready *before* the
  // bot connects to the server rather than racing the first player check
  // against it - have something to await. Never rejects: load errors are
  // already caught and logged inside, this just resolves once that's done
  // either way.
  private datasetsReady: Promise<void> = Promise.resolve();
  // Same idea as datasetsReady, for the other two background-loaded
  // sources kicked off in initialize() below (ASN index, Tor exit list) -
  // tracked so waitForAllReady() can gate the first server connection on
  // every download actually finishing, not just datasets.
  private asnReady: Promise<void> = Promise.resolve();
  private torReady: Promise<void> = Promise.resolve();

  // v8.2 - see the import comment above for the full picture.
  private cooldown: ApiCooldownTracker;
  // Parsed once at construction - env vars don't change mid-process, so
  // re-parsing IPCHECK_DISABLED_SERVICES on every single check would just
  // redo the same split/trim/lowercase for no benefit.
  private disabledServices: Set<string>;
  private readonly defaultRateLimitCooldownSeconds: number;
  // v8.3 - per-service enable/key config.json overrides (see import comment
  // above). Defaults to DEFAULT_APIS_CONFIG until initialize() runs with a
  // real AppConfig, same fallback pattern as detectionConfig/datasetsConfig.
  private apisConfig: ApisConfig = DEFAULT_APIS_CONFIG;

  private constructor() {
    this.logger = Logger.getInstance();
    this.cache = CacheService.getInstance();
    this.listManager = ListManager.getInstance();
    this.customBanManager = CustomBanManager.getInstance();
    this.asnIndex = AsnIndex.getInstance();
    this.cooldown = ApiCooldownTracker.getInstance();
    this.disabledServices = new Set(
      (process.env.IPCHECK_DISABLED_SERVICES || '')
        .split(',')
        .map(s => s.trim().toLowerCase())
        .filter(Boolean)
    );
    const configuredCooldownMinutes = parseFloat(process.env.IPCHECK_RATE_LIMIT_COOLDOWN_MINUTES || '');
    this.defaultRateLimitCooldownSeconds = (isNaN(configuredCooldownMinutes) || configuredCooldownMinutes <= 0)
      ? 60 * 60 // 60 minutes
      : configuredCooldownMinutes * 60;
    // These two hold their own state independent of AppConfig (they load
    // their JSON files eagerly, same as ListManager/CacheService), so they
    // can be constructed here; the config-dependent detectors below are
    // (re)configured in initialize() once AppConfig is available.
    this.networkReputationStore = NetworkReputationStore.getInstance();
    this.ipReputationStore = IpReputationStore.getInstance();
    this.reverseDnsService = ReverseDnsService.getInstance(this.detectionConfig.reverse_dns);
    this.networkAgeService = NetworkAgeService.getInstance(this.detectionConfig.network_age);
    this.residentialProxyDetector = ResidentialProxyDetector.getInstance(this.detectionConfig.residential_proxy);
    this.riskEngine = new RiskScoringEngine(this.detectionConfig.weights, this.detectionConfig.thresholds, this.logger);
    this.datasetLoader = DatasetLoader.getInstance();
    // Shared keep-alive agents (see utils/HttpAgents.ts) reuse TCP+TLS
    // connections across the many small requests this service makes,
    // instead of paying a fresh handshake (and, for HTTPS, a fresh TLS
    // negotiation) on every single call, and cache DNS resolution for the
    // ~15 distinct third-party API hosts this queries repeatedly over the
    // process lifetime - a real, measurable latency cut with no accuracy
    // trade-off. Shared (not locally constructed) so every other outbound
    // client in the project pools against the same connection/DNS cache.
    this.httpClient = axios.create({
      timeout: 2500,
      httpAgent: sharedKeepAliveHttpAgent,
      httpsAgent: sharedKeepAliveHttpsAgent,
      headers: { 'User-Agent': 'WizanthiAntiVpn/7.0', 'Accept': 'application/json' },
      // This client fans out to ~15 third-party IP-intel APIs per
      // connection (see the Layer 1 methods below) - a cap keeps one
      // misbehaving/compromised endpoint from returning an oversized body
      // and ballooning memory across a burst of concurrent player checks.
      // Every response here is expected to be a small JSON object.
      maxContentLength: 10 * 1024 * 1024,
      maxBodyLength: 10 * 1024 * 1024,
    });
  }

  static getInstance(config?: AppConfig): IpChecker {
    if (!IpChecker.instance) IpChecker.instance = new IpChecker();
    if (config && !IpChecker.instance.isInitialized) IpChecker.instance.initialize(config);
    return IpChecker.instance;
  }

  private initialize(config: AppConfig): void {
    this.config = config;
    this.isInitialized = true;
    // config.detection is always populated by ConfigManager (deep-merged
    // against DEFAULT_DETECTION_CONFIG - see ConfigManager.load()), but
    // fall back defensively in case IpChecker is ever wired up without
    // going through ConfigManager (e.g. in a test harness).
    this.detectionConfig = config.detection || DEFAULT_DETECTION_CONFIG;
    this.apisConfig = config.apis || DEFAULT_APIS_CONFIG;
    this.reverseDnsService = ReverseDnsService.getInstance(this.detectionConfig.reverse_dns);
    this.networkAgeService = NetworkAgeService.getInstance(this.detectionConfig.network_age);
    this.residentialProxyDetector = ResidentialProxyDetector.getInstance(this.detectionConfig.residential_proxy);
    this.riskEngine.updateConfig(this.detectionConfig.weights, this.detectionConfig.thresholds);
    this.networkReputationStore.configure({
      ipv4Prefix: this.detectionConfig.cidr_reputation.ipv4_prefix,
      ipv6Prefix: this.detectionConfig.cidr_reputation.ipv6_prefix,
      minSamplesForScore: this.detectionConfig.cidr_reputation.min_samples_for_score,
    });
    // v8.1: data/datasets - kick off the first load right away and start
    // the periodic reload timer if configured. Unlike the Tor list/ASN
    // index below, this one is *not* purely fire-and-forget: index.ts
    // awaits waitForDatasetsReady() before connecting to the server, so an
    // operator's dataset-sourced bans/whitelist are actually in effect for
    // the very first connection instead of racing the first few player
    // checks against a still-loading index.
    this.datasetsConfig = config.datasets || DEFAULT_DATASETS_CONFIG;
    this.datasetExcludedCountries = new Set(
      (this.datasetsConfig.exclude_countries || []).map(c => c.trim().toUpperCase()).filter(Boolean)
    );
    this.datasetsReady = this.datasetLoader.loadAll(this.datasetsConfig).catch((e) => this.logger.error('DatasetLoader: initial load failed', e));
    this.datasetLoader.startAutoReload(this.datasetsConfig);
    // FP-hardening (v8.4): after every dataset (re)load, prune
    // 'Dataset'-method blacklist entries whose backing dataset entry no
    // longer exists - so an operator removing a bad file actually unbans
    // its victims. The pruned IPs' cached (banned) verdicts are dropped
    // too, so their next connection gets a fresh full-pipeline check
    // (detection unchanged - if any OTHER layer still flags them, they're
    // re-banned on that evidence).
    this.datasetLoader.onLoaded(() => this.pruneStaleDatasetBans());
    this.logger.info('IpChecker v8.0 initialized - local ASN index, early-exit scoring, keep-alive HTTP, ASN-verdict cache, weighted reputation-scoring engine');
    // Kick off the first Tor list load and ASN index load in the
    // background so the very first player check doesn't have to wait on
    // either; both are idempotent and safe to call speculatively here.
    this.torReady = this.refreshTorExitList().catch((e) => this.logger.warn('IpChecker: initial Tor exit-list refresh failed', e));
    this.asnReady = this.asnIndex.init().catch((e) => this.logger.warn('IpChecker: initial ASN index refresh failed', e));
  }

  // Resolves once the initial data/datasets load (kicked off in
  // initialize() above) has finished - or immediately, if initialize()
  // hasn't run yet / datasets are disabled. Called from index.ts's startup
  // sequence so the bot connects to the server only after its dataset
  // indexes are actually populated.
  async waitForDatasetsReady(): Promise<void> {
    await this.datasetsReady;
  }

  // See the onLoaded registration in initialize(). An entry is still valid
  // only if the freshly-rebuilt dataset index still matches its IP - ASN
  // entries never wrote the blacklist (they quarantine), so isIpMatch +
  // lookupMmdb is the complete check.
  private pruneStaleDatasetBans(): void {
    try {
      const pruned = this.listManager.pruneBlacklistByMethod('Dataset', (ip) =>
        !!(this.datasetLoader.isIpMatch(ip) || this.datasetLoader.lookupMmdb(ip))
      );
      for (const ip of pruned) this.cache.delete(ip);
    } catch (e) {
      this.logger.warn('IpChecker: dataset blacklist prune failed', e);
    }
  }

  // Resolves once every background-loaded source kicked off in initialize()
  // - datasets, the ASN index, and the Tor exit list - has finished its
  // first load (success or failure; each already logs/swallows its own
  // error above so this never rejects). index.ts awaits this before
  // connecting to the server, so a fresh install with a large dataset/list
  // corpus makes its very first join decision with everything actually
  // downloaded, instead of racing the first few player checks against
  // still-loading indexes.
  async waitForAllReady(): Promise<void> {
    await Promise.all([this.datasetsReady, this.asnReady, this.torReady]);
  }

  // ========================================================================
  // MAIN CHECK METHOD
  // ========================================================================

  async checkIp(ip: string): Promise<IpCheckResult> {
    // Concurrent-connection dedup - see field comment above.
    const pending = this.inFlight.get(ip);
    if (pending) return pending;

    const promise = this.checkIpInternal(ip).finally(() => {
      this.inFlight.delete(ip);
    });
    this.inFlight.set(ip, promise);
    return promise;
  }

  // Full, cache-bypassing re-check - used by QuarantineReviewer to
  // re-verify a soft quarantine with the complete pipeline. Drops the
  // cached (quarantine) verdict first so checkIpInternal actually re-runs
  // everything instead of returning the entry under review.
  async recheckIp(ip: string): Promise<IpCheckResult> {
    this.cache.delete(ip);
    return this.checkIp(ip);
  }

  // FP-hardening: SOFT (quarantine) verdicts cache for a much shorter
  // window than hard/clean ones - a possibly-wrong single-signal verdict
  // must come back up for a full re-evaluation quickly instead of
  // re-firing off the cache on every reconnect for 24h. Hard bans and
  // clean results keep the global TTL unchanged.
  private static readonly SOFT_RESULT_TTL_MS = 45 * 60 * 1000; // 45 min
  private cacheResult(ip: string, result: IpCheckResult): void {
    if (result.ban_confidence === 'soft') {
      this.cache.set(ip, result, IpChecker.SOFT_RESULT_TTL_MS);
    } else {
      this.cache.set(ip, result);
    }
  }

  private async checkIpInternal(ip: string): Promise<IpCheckResult> {
    // === LAYER 0: INSTANT CHECKS (SYNC) ===
    if (this.listManager.isWhitelisted(ip)) {
      return this.createCleanResult(ip, 'Whitelisted', '', '', '');
    }
    if (this.listManager.isPrivateIP(ip)) {
      return this.createCleanResult(ip, 'Local', '', '', '');
    }
    if (this.listManager.isBlacklisted(ip)) {
      // Operator-curated blacklist -> hard ban. vpnDetection recorded as
      // false: the blacklist entry is not itself proof of a VPN category, and
      // marking it as one would re-inflate this IP's vpn reputation on every
      // subsequent sighting.
      this.recordReputationObservation(ip, true, false, 100);
      return this.createBanResult(ip, 'Blacklisted', '', 'Blacklisted', 'Blacklisted', 100, 'hard');
    }
    if (this.customBanManager.isCustomBanned(ip)) {
      const banInfo = this.customBanManager.getBanInfo(ip);
      return this.createBanResult(ip, 'Custom Ban', '', banInfo?.reason || 'Custom ban', `Duration: ${banInfo?.duration_minutes === 0 ? 'Permanent' : banInfo?.duration_minutes + 'min'}`, 100, 'hard');
    }

    const cached = this.cache.get(ip);
    if (cached) return cached;

    // === LAYER 0.25: CUSTOM DATASETS - IP/CIDR/MMDB (SYNC, ZERO NETWORK
    // LATENCY) === (requirement: "support database/dataset of ips or asns"
    // - see DatasetLoader.ts)
    // Checked here, before any network call, for the same reason Layer
    // 0/0.5 already are. In the default 'instant' mode a match here is
    // exactly as authoritative as the existing curated bulk lists /
    // VERIFIED_HOSTING_VPN_ASNS - this is data the operator deliberately
    // dropped into data/datasets, not a guess. In 'corroborate' mode the
    // match is only remembered (in `datasetMatch`, used again in Layer 0.5
    // for ASN entries, and finally folded into the weighted scoring
    // engine) instead of deciding anything by itself.
    //
    // The ASN-index lookup is hoisted up here (from its old Layer 0.5
    // position - it's a pure, synchronous, in-memory binary search, so the
    // reorder changes nothing about what it returns) because the dataset
    // country exemption below needs the IP's country before the first
    // dataset check runs.
    const asnHit = this.asnIndex.lookup(ip);
    // datasets.exclude_countries: players from these countries are exempt
    // from the DATASET checks only - no 'instant' dataset ban, no
    // dataset_match composite signal. Every other layer (verified-hosting
    // ASN, API battery, keywords, Tor, ML, composite) still applies to
    // them in full below. An IP the index can't attribute stays checkable.
    const datasetCountryExcluded = !!(asnHit && asnHit.country && this.datasetExcludedCountries.has(asnHit.country));
    if (datasetCountryExcluded) {
      this.logger.debug(`Dataset checks skipped for ${ip} - country ${asnHit!.country} is in datasets.exclude_countries (all other checks still apply)`);
    }
    let datasetMatch: DatasetMatch | null = null;
    if (this.datasetsConfig.enabled && !datasetCountryExcluded) {
      datasetMatch = this.datasetLoader.isIpMatch(ip) || this.datasetLoader.lookupMmdb(ip);
      if (datasetMatch && this.datasetsConfig.mode === 'instant') {
        // Only reached when the operator has explicitly opted into 'instant'
        // mode (default is now 'corroborate', where a dataset hit only feeds
        // the weighted composite). Still a hard, immediate ban (operator's
        // own deliberate data - detection unchanged), but FP-hardened in
        // three ways (v8.4):
        //  - the blacklist entry stays tagged 'Dataset' and is now PRUNED on
        //    dataset reload if its backing entry disappears (see
        //    pruneStaleDatasetBans) - removing a bad file actually unbans
        //    its victims instead of leaving them permanently blacklisted;
        //  - no ML training sample: "some list contained this IP" teaches
        //    the model nothing about the IP's own features, and a bad list
        //    used to inject label=1 samples that degraded every later
        //    prediction;
        //  - reputation records a non-ban observation (banned=false) so one
        //    stale list entry can't seed the IP/subnet reputation stores
        //    with "was banned" evidence that then corroborates itself.
        const result = this.createBanResult(ip, 'Unknown', '', datasetMatch.source, datasetMatch.source, 88, 'hard');
        result.threat_level = 'high';
        result.dataset_match = datasetMatch;
        this.cacheResult(ip, result);
        this.listManager.addToBlacklist(ip, `Custom dataset ${datasetMatch.type} match: ${datasetMatch.value} [${datasetMatch.source}]`, 'Dataset');
        this.logger.warn(`BLOCKED (Dataset): ${ip} - ${datasetMatch.type} match "${datasetMatch.value}" from ${datasetMatch.source}`);
        this.recordReputationObservation(ip, false, false, 88);
        return result;
      }
    }

    // === LAYER 0.5: LOCAL ASN INDEX (SYNC, ZERO NETWORK LATENCY) ===
    // Which network announces this IP is a verifiable BGP fact, looked up
    // instantly from the in-memory table built by AsnIndex (see that file)
    // instead of a per-connection API call. Two ways this can decide the
    // verdict without touching any of the network APIs below:
    //   1. The ASN is already in VERIFIED_HOSTING_VPN_ASNS - the same
    //      curated, individually-confirmed allowlist that already governs
    //      ListManager's bulk static-range block (Layer 0). Trusting a live
    //      index hit exactly as much as that bulk list is consistent, not
    //      a lowered bar - it just also catches IPs the 6-hourly bulk
    //      refresh hasn't picked up yet.
    //   2. The ASN was corroborated as hosting/datacenter via the full API
    //      battery for a *different* IP recently (asnVerdictCache) - so a
    //      newly-seen IP in that same network doesn't have to repeat the
    //      whole round to reach the same, already-proven conclusion.
    // (asnHit itself was looked up above, before Layer 0.25, so the dataset
    // country exemption could use it - see that comment.)
    if (asnHit) {
      if (VERIFIED_HOSTING_VPN_ASNS_SET.has(asnHit.asn)) {
        // FP-hardening: a purely offline ASN-index hit is a single,
        // uncorroborated signal. It still acts immediately, but only as a
        // SOFT (quarantine + human-review) ban - never a permanent blacklist
        // entry and never recorded as a "ban" in the reputation stores - so a
        // mislisted residential customer of a mixed residential/hosting ASN
        // can never be permanently false-banned on this signal alone. A
        // genuine datacenter IP is still additionally caught (and hardened)
        // by the API battery below on its next check.
        const result = this.createBanResult(ip, 'Unknown', '', asnHit.name || `AS${asnHit.asn}`, asnHit.name || `AS${asnHit.asn}`, 90, 'soft');
        result.is_hosting = true; result.is_datacenter = true; result.threat_level = 'high';
        this.cacheResult(ip, result);
        this.logger.warn(`QUARANTINE (ASN-Index): ${ip} - AS${asnHit.asn} ${asnHit.name}`);
        this.recordReputationObservation(ip, false, false, result.risk_score || 90);
        return result;
      }
      // v8.1: dataset-sourced ASN block-list (see DatasetLoader.ts) - same
      // country exemption and corroborate handling as the IP/CIDR/MMDB
      // check above. Skipped if the IP/CIDR/MMDB check already found a
      // match, to avoid a redundant lookup.
      //
      // FP-hardening (v8.4): an ASN entry is categorically broader than an
      // IP/CIDR entry - ONE mislisted line bans an entire network operator
      // (the shipped community lists have been observed carrying major
      // residential ISPs' ASNs). So even in 'instant' mode an ASN match now
      // produces a SOFT quarantine (immediate, time-boxed, review-webhooked,
      // re-verified by QuarantineReviewer) instead of a permanent hard ban +
      // blacklist write. Detection is not reduced - the player is still
      // banned on sight for the quarantine window, and a genuinely-hosting
      // ASN gets escalated to a hard ban by the reviewer's full API
      // re-check minutes later; only the *permanence* of an uncorroborated
      // whole-ASN verdict is gone. Additionally, a dataset ASN whose
      // registered name matches TRUSTED_PROVIDERS (a known residential/
      // mobile carrier) is ignored outright with a warning - a hosting ASN
      // never carries a consumer-carrier name, so this costs nothing.
      if (!datasetMatch && this.datasetsConfig.enabled && !datasetCountryExcluded) {
        const asnDatasetMatch = this.datasetLoader.isAsnMatch(asnHit.asn);
        if (asnDatasetMatch) {
          const asnNameNorm = this.normalizeProviderText(asnHit.name || '');
          const trustedCarrier = asnNameNorm && this.isTrustedProvider(asnHit.name || '');
          if (trustedCarrier) {
            this.logger.warn(`Dataset ASN entry IGNORED: AS${asnHit.asn} "${asnHit.name}" [${asnDatasetMatch.source}] matches a trusted residential/mobile carrier - likely a poisoned dataset line; prune it from the source file`);
          } else {
            datasetMatch = asnDatasetMatch;
            if (this.datasetsConfig.mode === 'instant') {
              const result = this.createBanResult(ip, 'Unknown', '', asnHit.name || `AS${asnHit.asn}`, asnDatasetMatch.source, 88, 'soft');
              result.is_hosting = true; result.threat_level = 'high';
              result.dataset_match = asnDatasetMatch;
              this.cacheResult(ip, result);
              this.logger.warn(`QUARANTINE (Dataset-ASN): ${ip} - AS${asnHit.asn} [${asnDatasetMatch.source}]`);
              this.recordReputationObservation(ip, false, false, 88);
              return result;
            }
          }
        }
      }
      const cachedAsnVerdict = this.asnVerdictCache.get(asnHit.asn);
      if (cachedAsnVerdict && Date.now() - cachedAsnVerdict.at <= this.asnVerdictTtlMs && (cachedAsnVerdict.hosting || cachedAsnVerdict.datacenter)) {
        // FP-hardening: a cached hosting verdict was corroborated for a
        // *different* IP in this ASN, not for this one - so it acts only as a
        // SOFT quarantine + review, never a permanent blacklist entry.
        //
        // v8.4: additionally skipped when the ASN's registered name matches
        // a trusted residential/mobile carrier - on a mixed-use ASN (a
        // carrier that also sells server space, or one compromised host in
        // a consumer pool) one corroborated hosting IP used to quarantine
        // every other customer of that carrier for 6h. The full API battery
        // below still checks this IP individually, so a genuinely-hosting
        // IP inside a carrier ASN is still caught - just on its own
        // evidence rather than a neighbor's.
        if (this.isTrustedProvider(asnHit.name || '')) {
          this.logger.debug(`ASN-cache verdict skipped for ${ip}: AS${asnHit.asn} "${asnHit.name}" matches a trusted carrier - checking this IP on its own evidence instead`);
        } else {
          const result = this.createBanResult(ip, 'Unknown', '', asnHit.name || `AS${asnHit.asn}`, asnHit.name || `AS${asnHit.asn}`, 85, 'soft');
          result.is_hosting = cachedAsnVerdict.hosting; result.is_datacenter = cachedAsnVerdict.datacenter;
          result.threat_level = 'high';
          this.cacheResult(ip, result);
          this.logger.warn(`QUARANTINE (ASN-Cache): ${ip} - AS${asnHit.asn} ${asnHit.name}`);
          this.recordReputationObservation(ip, false, false, result.risk_score || 85);
          return result;
        }
      }
    }

    // === LAYER 1: REAL IP-INTELLIGENCE APIS (PARALLEL, EARLY-EXIT) ===
    // These are services actually built to detect VPN/proxy/hosting usage,
    // as opposed to guessing from unrelated network probes. Instead of
    // waiting on Promise.allSettled for every single one (worst case: the
    // full timeout of whichever call is slowest, even after a verdict is
    // already certain), gatherApiVerdict() consumes results as they land
    // and stops early the moment a ban is already confirmed - a real
    // player who's actually flagged rarely needs all sources to agree
    // before the threshold is cleared. A clean player still needs the
    // full set, since a plain absence of positive signal from a partial
    // set never proves innocence - so there is no accuracy trade-off here,
    // only wasted latency removed from the positive path.
    const apiStart = Date.now();
    const verdict = await this.gatherApiVerdict(ip);
    this.logger.debug(`API verdict gathered in ${Date.now() - apiStart}ms (early-exit)`);

    let { country, city, isp, org, vpnScore, proxyScore, torScore, hostingScore, datacenterScore,
      vpnSources, proxySources, torSources, hostingSources, datacenterSources } = verdict;
    // Count of *distinct* sources that flagged each category. A single
    // mistaken/stale API result should never be enough on its own to ban a
    // real player - true VPN/proxy IPs are almost always flagged by more
    // than one independent service, so requiring corroboration costs very
    // little recall while removing most single-source false positives.

    // Feature vector for the ML layer built once here - reused for every
    // training-sample capture below and for the Layer 3.5 corroboration
    // check, so it's always built from the exact same completed API round.
    const mlFeatures = this.mlDetector.extractFeatures({
      isp, org, asn: asnHit?.asn, verifiedAsnHit: false,
      vpnScore, vpnSources, proxyScore, proxySources,
      hostingScore, hostingSources, datacenterScore, datacenterSources, torScore,
    });
    // Computed here (moved up from the old Layer 3.5 position) purely so
    // it's available both to Layer 3.5 below AND to the new weighted
    // scoring engine/ResidentialProxyDetector - predict() is a pure,
    // in-memory computation with no I/O, so reordering it changes nothing
    // about what it returns.
    const mlPrediction = this.mlDetector.predict(mlFeatures);

    // === LAYER 2: TRUSTED PROVIDERS (checked BEFORE keyword/ban logic) ===
    // A known residential/mobile carrier is never banned even if its org
    // string happens to also match a keyword below.
    const combined = `${isp} ${org}`.toLowerCase().trim();
    if (this.isTrustedProvider(combined)) {
      const result = this.createCleanResult(ip, country, city, isp, org);
      this.cacheResult(ip, result);
      this.listManager.addToWhitelist(ip, `Trusted: ${isp}`);
      this.mlDetector.addTrainingSample(mlFeatures, 0);
      this.recordReputationObservation(ip, false, false, 0);
      return result;
    }

    // API verdict: require BOTH a weighted-score threshold AND at least two
    // distinct sources agreeing. This is the key change for false-positive
    // control - it means one API having stale/wrong data for an IP can no
    // longer single-handedly ban a real player, while a genuine VPN/proxy
    // IP (which real detection services largely agree on) still clears the
    // bar easily. Computed straight from the just-completed API round and
    // the local ASN index - all zero-latency, no network - so they're
    // available for the FAST BAN PATH below before any Layer 2.5 signal is
    // gathered.
    const vpnConfirmed = vpnScore >= 3 && vpnSources >= 2;
    const proxyConfirmed = proxyScore >= 3 && proxySources >= 2;
    const torConfirmed = torScore >= 2; // Tor is cross-checked again later against the official exit list
    const hostingConfirmed = hostingScore >= 4 && hostingSources >= 2;
    const datacenterConfirmed = datacenterScore >= 4 && datacenterSources >= 2;
    const isVerifiedHostingAsn = !!(asnHit && VERIFIED_HOSTING_VPN_ASNS_SET.has(asnHit.asn));

    // Synchronous, in-memory reputation reads (zero latency) - used by both
    // the fast ban path immediately below and the composite path further
    // down, so read once here.
    const cidrReputation = this.networkReputationStore.getReputationScore(ip);
    const ipReputation = this.ipReputationStore.getReputationScore(ip);

    // === FAST BAN PATH (INSTANT) ===
    // The moment the API battery has already corroborated a VPN/proxy/Tor/
    // hosting/datacenter verdict (2+ independent sources), ban NOW. The
    // Layer 2.5 signals below (reverse-DNS, network-age WHOIS,
    // residential-proxy probe) only ever back the *weaker* composite path -
    // they cannot turn an already-confirmed ban into a non-ban, so waiting
    // on the two network-bound ones (network-age + residential-proxy) here
    // would only add latency to a decision that's already final. The result
    // still carries the zero-latency reputation scores; the composite-only
    // enrichment fields (network age / residential score / reverse-DNS
    // hostname) are simply left unset on this fast path.
    if (vpnConfirmed || proxyConfirmed || torConfirmed || hostingConfirmed || datacenterConfirmed) {
      // FP-hardening: 2+ independent sources agreeing on an *anonymiser*
      // category (Tor / VPN / proxy) is the highest-confidence detection ->
      // permanent 'hard' ban + persistent blacklist entry. A hosting/
      // datacenter-only confirmation is genuine but a legitimate player can
      // sit behind a corporate/cloud gateway, so it is a SOFT quarantine +
      // review instead (time-boxed, not blacklisted).
      const strongConfirm = vpnConfirmed || proxyConfirmed || torConfirmed;
      const confidence: 'hard' | 'soft' = strongConfirm ? 'hard' : 'soft';
      const riskScore = torConfirmed ? 100 : vpnConfirmed && proxyConfirmed ? 95 : vpnConfirmed ? 90 : proxyConfirmed ? 85 : 70;
      const threatLevel = torConfirmed ? 'critical' : vpnConfirmed ? 'high' : proxyConfirmed ? 'high' : 'medium';
      const result = this.createBanResult(ip, country, city, isp, org, riskScore, confidence);
      result.is_vpn = vpnConfirmed;
      result.is_proxy = proxyConfirmed;
      result.is_tor = torConfirmed;
      result.is_hosting = hostingConfirmed;
      result.is_datacenter = datacenterConfirmed;
      result.threat_level = threatLevel;
      result.subnet_reputation_score = cidrReputation.score;
      result.ip_reputation_score = ipReputation.score;
      result.dataset_match = datasetMatch;
      if (asnHit) { result.asn = asnHit.asn; result.asn_country = asnHit.country || undefined; }
      this.cacheResult(ip, result);
      // Only a hard ban writes the persistent blacklist entry - a soft
      // quarantine must stay re-evaluable (never silently become permanent).
      if (confidence === 'hard') {
        this.listManager.addToBlacklist(ip, `API (${vpnScore}V/${vpnSources}src, ${proxyScore}P/${proxySources}src, ${torScore}T, ${hostingScore}H/${hostingSources}src): ${isp}`, 'API');
      }
      // FP-hardening (v8.4): the ML model only ever trains on HARD
      // (2+-independent-source) outcomes. Soft quarantines are hypotheses,
      // not confirmed positives - feeding them in as label=1 built a
      // feedback loop where the model learned its own unverified guesses
      // (its positive sample stream was dominated by the very single-signal
      // paths it was supposed to be a check on). QuarantineReviewer now
      // supplies the training label for soft verdicts once the re-check
      // resolves them (escalated -> 1, refuted -> 0), which is strictly
      // better data than labeling them 1 at quarantine time.
      if (confidence === 'hard') this.mlDetector.addTrainingSample(mlFeatures, 1);
      this.logger.warn(`${confidence === 'hard' ? 'BLOCKED' : 'QUARANTINE'} (API, instant): ${ip} - ${isp} [V:${vpnScore}/${vpnSources} P:${proxyScore}/${proxySources} T:${torScore} H:${hostingScore}/${hostingSources}]`);
      // Remember this ASN as confirmed-hosting so the next IP seen inside
      // it (before the next bulk-list refresh) gets an instant local
      // verdict instead of repeating the whole API round - see Layer 0.5.
      if (asnHit && (hostingConfirmed || datacenterConfirmed)) {
        this.asnVerdictCache.set(asnHit.asn, { hosting: hostingConfirmed, datacenter: datacenterConfirmed, at: Date.now() });
      }
      // Only a hard ban counts as a "ban" for reputation; vpnDetection only
      // when a VPN/proxy category was actually confirmed.
      this.recordReputationObservation(ip, confidence === 'hard', vpnConfirmed || proxyConfirmed, riskScore);
      return result;
    }

    // === LAYER 2.5: REPUTATION SIGNAL GATHERING (requirements #1-#3, #10) ===
    // Only reached when nothing above already banned - i.e. the connection
    // needs the weaker composite path to decide. Everything here is
    // read-only/cached/fail-open and never decides anything by itself - it
    // only feeds RiskScoringEngine below. Reverse-DNS is almost always a
    // cache hit here already (the Layer 1 battery above just performed the
    // same lookup via checkReverseDNS, which now delegates to the same
    // cached ReverseDnsService). Network age and the residential-proxy
    // detector are the only two calls that can add real latency on a
    // cache-miss, and both are individually timeout-bounded and cached so
    // the cost is only ever paid once per ASN/IP within their cache windows.
    // Fail-open, same discipline as every Layer 1 API (safeGet): a transient
    // failure in any of these signal-gathering calls must degrade to a
    // neutral "no signal" value, never reject the whole player check. These
    // services are individually documented as fail-open, but the defensive
    // .catch here guarantees it at the call site regardless.
    const reverseDnsResult = await this.reverseDnsService.lookup(ip)
      .catch(() => ({ ip, hostname: null, suspicious: false, matchedKeyword: null }));
    const [networkAgeResult, residentialProxyResult] = await Promise.all([
      this.networkAgeService.getNetworkAge(ip, asnHit?.asn ?? null)
        .catch(() => ({ asn: asnHit?.asn ?? null, allocationDate: null, ageDays: null, isRecent: false })),
      this.residentialProxyDetector.evaluate({
        ip, isp, org, asn: asnHit?.asn ?? null,
        hostingScore, vpnScore, proxyScore,
        reverseDnsSuspicious: reverseDnsResult.suspicious,
        cidrReputationBad: cidrReputation.bad,
        ipReputationBad: ipReputation.bad,
        mlScore: mlPrediction.score,
      }).catch(() => ({ score: 0, confirmed: false, reasons: [], independentSignals: 0 })),
    ]);

    // Weighted risk assessment (requirement #4) - computed unconditionally
    // once we reach this point so every possible outcome from here on
    // (keyword ban, ML ban, the new composite ban, or clean) is scored and
    // logged the same way (requirement #8), and so every IpCheckResult
    // returned past this point can be enriched with the same breakdown for
    // debugging/webhooks/dashboards.
    const riskAssessment = this.riskEngine.score(ip, {
      knownVpnApi: vpnConfirmed,
      hostingAsn: hostingConfirmed || datacenterConfirmed || isVerifiedHostingAsn,
      residentialProxy: residentialProxyResult.confirmed,
      tor: torConfirmed,
      badReverseDns: reverseDnsResult.suspicious,
      ipReputation: ipReputation.bad,
      cidrReputation: cidrReputation.bad,
      mlScore: mlPrediction.score,
      goodReputationBonus: ipReputation.good ? -10 : 0,
      // Only ever true here when datasets.mode = 'corroborate' - an
      // 'instant' match would already have returned above.
      datasetMatch: !!datasetMatch,
      datasetMatchType: datasetMatch?.type,
    });

    const enrich = (result: IpCheckResult): IpCheckResult => {
      result.risk_level = riskAssessment.level;
      result.risk_breakdown = riskAssessment.breakdown;
      result.subnet_reputation_score = cidrReputation.score;
      result.ip_reputation_score = ipReputation.score;
      result.residential_proxy_score = residentialProxyResult.score;
      result.network_age_days = networkAgeResult.ageDays;
      result.reverse_dns_hostname = reverseDnsResult.hostname;
      result.dataset_match = datasetMatch;
      if (asnHit) { result.asn = asnHit.asn; result.asn_country = asnHit.country || undefined; }
      return result;
    };

    // === LAYER 3: KEYWORD MATCHING (brand-name / specific-provider list only) ===
    const normalized = this.normalizeProviderText(combined);
    if (this.matchesKeywords(normalized, VPN_KEYWORDS_NORMALIZED)) {
      // Single-signal brand-keyword match -> SOFT quarantine + review (a
      // reseller/transit org string can legitimately mention a VPN brand), so
      // it is not written to the persistent blacklist and not counted as a
      // "ban" in reputation. vpnDetection stays true - it is a genuine VPN
      // brand signal - so a real anonymiser still accrues reputation.
      const result = enrich(this.createBanResult(ip, country, city, isp, org, 80, 'soft'));
      result.is_vpn = true;
      this.cacheResult(ip, result);
      // No ML sample here (v8.4): a single-signal soft verdict is a
      // hypothesis - QuarantineReviewer supplies the label once resolved.
      this.recordReputationObservation(ip, false, true, 80);
      return result;
    }
    if (this.matchesKeywords(normalized, PROXY_KEYWORDS_NORMALIZED)) {
      const result = enrich(this.createBanResult(ip, country, city, isp, org, 80, 'soft'));
      result.is_proxy = true;
      this.cacheResult(ip, result);
      this.recordReputationObservation(ip, false, true, 80);
      return result;
    }
    // Hosting/datacenter brand matches are the fuzziest category (a
    // reseller ISP's org string can legitimately mention an upstream
    // hosting brand). Require at least one corroborating API signal before
    // banning on the keyword alone.
    const hasWeakHostingSignal = hostingScore > 0 || datacenterScore > 0;
    if (this.matchesKeywords(normalized, HOSTING_KEYWORDS_NORMALIZED) && hasWeakHostingSignal) {
      const result = enrich(this.createBanResult(ip, country, city, isp, org, 65, 'soft'));
      result.is_hosting = true;
      this.cacheResult(ip, result);
      this.recordReputationObservation(ip, false, false, 65);
      return result;
    }
    if (this.matchesKeywords(normalized, DATACENTER_KEYWORDS_NORMALIZED) && hasWeakHostingSignal) {
      const result = enrich(this.createBanResult(ip, country, city, isp, org, 65, 'soft'));
      result.is_datacenter = true;
      this.cacheResult(ip, result);
      this.recordReputationObservation(ip, false, false, 65);
      return result;
    }

    // === LAYER 3.5: ML CORROBORATION (learned from THIS server's own
    // confirmed history above - see MlDetector.ts) ===
    // Only ever reached for a connection that every fixed threshold above
    // already let through. predict() itself refuses to return anything but
    // a neutral, zero-effect score until the model has at least
    // MIN_TRAINING_SAMPLES real confirmed examples from this exact server
    // to learn from, so this cannot influence a verdict on a fresh install.
    // The bar here (score>=85 AND confidence>=0.6) is deliberately higher
    // than the fixed-threshold layers above it, for the same reason this
    // whole file requires 2+ corroborating sources everywhere else: one
    // more (learned, not hand-tuned) signal shouldn't get to unilaterally
    // ban a real player either.
    if (mlPrediction.score >= 85 && mlPrediction.confidence >= 0.6) {
      // A single learned signal -> SOFT quarantine + review, never a
      // permanent blacklist entry or a reputation "ban".
      const result = enrich(this.createBanResult(ip, country, city, isp, org, mlPrediction.score, 'soft'));
      result.threat_level = mlPrediction.threatLevel;
      this.cacheResult(ip, result);
      // No self-training on the model's own prediction (v8.4) - that was a
      // pure echo chamber (predict -> label own output 1 -> retrain).
      // QuarantineReviewer supplies the label once the re-check resolves.
      this.logger.warn(`QUARANTINE (ML): ${ip} - ${isp} [score:${mlPrediction.score} conf:${mlPrediction.confidence}]`);
      this.recordReputationObservation(ip, false, false, mlPrediction.score);
      return result;
    }

    // === LAYER 3.75: WEIGHTED COMPOSITE SCORING (requirements #4, #9, #10) ===
    // Only ever reached once every fixed-threshold, keyword, and ML path
    // above has already let the connection through. This is the ONE place
    // the new CIDR reputation / IP reputation / reverse-DNS / network-age /
    // residential-proxy signals can, together, still result in a ban - and
    // even then only when:
    //   (a) the combined weighted score reaches High Risk or Critical, AND
    //   (b) at least `min_independent_signals_for_ban` distinct weighted
    //       categories fired (default 3).
    // This is what satisfies requirement #9's false-positive guards: a
    // hosting ASN alone, a suspicious reverse-DNS hostname alone, one API
    // result alone, or a residential-ISP classification alone can never
    // reach this bar by itself - they can only ever be one line in a
    // breakdown that needs several independent lines to agree.
    const compositeConfirmed =
      (riskAssessment.level === 'high_risk' || riskAssessment.level === 'critical') &&
      riskAssessment.independentSignals >= this.detectionConfig.min_independent_signals_for_ban;

    if (compositeConfirmed) {
      // Reached only after >= min_independent_signals_for_ban distinct
      // weighted signals agreed at high-risk/critical. Still treated as SOFT
      // (quarantine + review): several of the composite inputs (reverse-DNS,
      // CIDR/IP reputation) are individually noisy, so this acts immediately
      // but time-boxed and human-reviewed rather than becoming a permanent
      // blacklist entry that could snowball a shared residential subnet.
      const result = enrich(this.createBanResult(ip, country, city, isp, org, riskAssessment.score, 'soft'));
      result.threat_level = RiskScoringEngine.toThreatLevel(riskAssessment.level);
      // None of the individual composite signals are a "confirmed" VPN/
      // proxy/Tor/hosting verdict on their own (that's the whole point),
      // so is_vpn/is_proxy/is_tor stay false; is_hosting only reflects a
      // verified hosting ASN if that's genuinely one of the contributing
      // signals. residential_proxy_score/subnet_reputation_score on the
      // result (set by enrich()) carry the actual reasoning.
      result.is_vpn = false;
      result.is_proxy = false;
      result.is_tor = false;
      result.is_hosting = isVerifiedHostingAsn;
      result.is_datacenter = false;
      this.cacheResult(ip, result);
      const breakdownLine = riskAssessment.breakdown.map(b => `${b.weight >= 0 ? '+' : ''}${b.weight} ${b.label}`).join(' ');
      this.logger.warn(`QUARANTINE (Composite): ${ip} - ${isp} | ${breakdownLine} | Final Score: ${riskAssessment.score} (${riskAssessment.level}, ${riskAssessment.independentSignals} independent signals)`);
      this.recordReputationObservation(ip, false, false, riskAssessment.score);
      return result;
    }

    // NOTE: the official Tor Project exit-list check used to live here as a
    // Layer 4 step that re-downloaded the full torbulkexitlist over HTTP for
    // every single non-cached IP. It's now `checkTorMembership()` in the
    // Layer 1 parallel batch above, reading from a cache refreshed on a
    // timer (see refreshTorExitList) - same authoritative source, no more
    // per-connection network round trip. A Tor match there already sets
    // torScore/torSources high enough to satisfy torConfirmed by itself.

    // === CLEAN ===
    const result = enrich(this.createCleanResult(ip, country, city, isp, org));
    // A clean verdict can still carry a nonzero "suspicious"-range score
    // (e.g. a couple of weak signals that didn't reach the composite ban
    // bar) - reflect that in threat_level/risk_score for visibility
    // (dashboards/webhooks) without treating it as a ban.
    if (riskAssessment.level !== 'safe') {
      result.risk_score = riskAssessment.score;
      result.threat_level = RiskScoringEngine.toThreatLevel(riskAssessment.level);
    }
    this.cacheResult(ip, result);
    this.listManager.addToWhitelist(ip, `Clean: ${isp}`);
    this.mlDetector.addTrainingSample(mlFeatures, 0);
    this.logger.info(`ALLOWED: ${ip} - ${isp} (${country}) | RiskScore:${riskAssessment.score} (${riskAssessment.level})`);
    this.recordReputationObservation(ip, false, false, riskAssessment.score);
    return result;
  }

  // ========================================================================
  // EARLY-EXIT VERDICT GATHERING
  // ========================================================================
  // Fires every Layer 1 API in parallel, but instead of blocking on
  // Promise.allSettled until the slowest one finishes (or times out), it
  // folds each result into the running verdict as soon as it lands and
  // stops waiting on the rest the moment a ban threshold is already met.
  // A clean verdict still requires every source to report in, since the
  // absence of a positive signal from a partial set never proves
  // innocence - so this only removes wasted latency from the positive
  // (ban) path, with no change to what counts as "confirmed".
  private isVerdictConfirmed(v: RunningVerdict): boolean {
    return (v.vpnScore >= 3 && v.vpnSources >= 2) ||
      (v.proxyScore >= 3 && v.proxySources >= 2) ||
      (v.torScore >= 2) ||
      (v.hostingScore >= 4 && v.hostingSources >= 2) ||
      (v.datacenterScore >= 4 && v.datacenterSources >= 2);
  }

  private applySignal(v: RunningVerdict, d: ApiSignal | null): void {
    if (!d) return;
    // Weak (derived) signals never overwrite identity fields - a PTR
    // hostname or RDAP org-name is not an ISP name, and letting it become
    // one both poisoned the trusted-provider check and fed the brand-
    // keyword layer garbage input.
    if (!d.weak) {
      if (d.country && d.country !== 'Unknown') v.country = d.country;
      if (d.city && d.city !== 'Unknown') v.city = d.city;
      if (d.isp && d.isp !== 'Unknown') v.isp = d.isp;
      if (d.org && d.org !== 'Unknown') v.org = d.org;
    }
    // Score always accrues (weak signals still contribute weight - no
    // detection reduction); the *Sources counts only ever reflect distinct
    // provenance FAMILIES of non-weak, purpose-built services, since those
    // counts are what clear the 2-source permanent-ban bar.
    const family = d.family || `anon:${Math.random()}`; // no family declared -> always distinct
    const bump = (flag: boolean | undefined, weight: number | undefined, score: 'vpnScore' | 'proxyScore' | 'torScore' | 'hostingScore' | 'datacenterScore', sources: 'vpnSources' | 'proxySources' | 'torSources' | 'hostingSources' | 'datacenterSources', families: 'vpnFamilies' | 'proxyFamilies' | 'torFamilies' | 'hostingFamilies' | 'datacenterFamilies') => {
      if (!flag) return;
      v[score] += weight || 1;
      if (!d.weak && !v[families].has(family)) {
        v[families].add(family);
        v[sources]++;
      }
    };
    bump(d.isVpn, d.vpnWeight, 'vpnScore', 'vpnSources', 'vpnFamilies');
    bump(d.isProxy, d.proxyWeight, 'proxyScore', 'proxySources', 'proxyFamilies');
    bump(d.isTor, d.torWeight, 'torScore', 'torSources', 'torFamilies');
    bump(d.isHosting, d.hostingWeight, 'hostingScore', 'hostingSources', 'hostingFamilies');
    bump(d.isDatacenter, d.datacenterWeight, 'datacenterScore', 'datacenterSources', 'datacenterFamilies');
  }

  private async gatherApiVerdict(ip: string): Promise<RunningVerdict> {
    const checks: Array<Promise<ApiSignal | null>> = [
      this.checkIpApi(ip),
      this.checkIpwhois(ip),
      this.checkIpapiCo(ip),
      this.checkIpinfo(ip),
      this.checkVpnApi(ip),
      this.checkProxyCheck(ip),
      this.checkIPQuality(ip),
      this.checkAbuseIPDB(ip),
      this.checkReverseDNS(ip),
      this.checkIpapiIs(ip),
      this.checkRdap(ip),
      this.checkTorMembership(ip),
      this.checkGetIpIntel(ip),
      this.checkIplocate(ip),
      this.checkIpregistry(ip),
    ];

    const verdict: RunningVerdict = {
      country: 'Unknown', city: 'Unknown', isp: 'Unknown', org: 'Unknown',
      vpnScore: 0, proxyScore: 0, torScore: 0, hostingScore: 0, datacenterScore: 0,
      vpnSources: 0, proxySources: 0, torSources: 0, hostingSources: 0, datacenterSources: 0,
      vpnFamilies: new Set(), proxyFamilies: new Set(), torFamilies: new Set(),
      hostingFamilies: new Set(), datacenterFamilies: new Set(),
    };

    // Tag each promise with its index so a settled one can be removed from
    // the "still waiting on" set without losing track of the others.
    const tagged = checks.map((p, idx) => p.then(v => ({ idx, v })).catch(() => ({ idx, v: null as ApiSignal | null })));
    let pending = new Set(tagged.map((_, i) => i));

    while (pending.size > 0) {
      const remaining = tagged.filter((_, i) => pending.has(i));
      const { idx, v } = await Promise.race(remaining);
      pending.delete(idx);
      this.applySignal(verdict, v);
      if (this.isVerdictConfirmed(verdict)) break; // ban already certain - stop waiting on slower sources
    }

    return verdict;
  }

  // ========================================================================
  // v8.2: SHARED URL-OVERRIDE / RATE-LIMIT-COOLDOWN HELPERS
  // ========================================================================

  // Builds the URL for a given service id: an operator-set
  // `<SERVICE_ID>_URL` env var wins (with {ip}/{key} placeholders
  // substituted) so any service can be pointed at a mirror/replacement
  // endpoint without a code change; otherwise falls back to the built-in
  // default, so behavior is 100% unchanged for anyone who hasn't set one.
  private resolveUrl(id: string, ip: string, defaultBuilder: (ip: string) => string, key?: string): string {
    const override = process.env[`${id.toUpperCase()}_URL`];
    if (!override) return defaultBuilder(ip);
    return override.replace(/\{ip\}/g, encodeURIComponent(ip)).replace(/\{key\}/g, key ? encodeURIComponent(key) : '');
  }

  // config.json's apis.<id>_api.enabled (default true) AND
  // IPCHECK_DISABLED_SERVICES (env var, kept for backwards compatibility)
  // both gate a service - either one can turn it off.
  private isServiceEnabled(id: string): boolean {
    if (this.disabledServices.has(id)) return false;
    return this.apisConfig[`${id}_api`]?.enabled !== false;
  }

  // config.json's apis.<id>_api.api_key wins if set (non-empty); otherwise
  // falls back to the service's existing env var, so a deployment that
  // already sets e.g. PROXYCHECK_API_KEY keeps working unchanged.
  private resolveApiKey(id: string, envVarName?: string): string | undefined {
    const configured = this.apisConfig[`${id}_api`]?.api_key;
    if (configured) return configured;
    return envVarName ? process.env[envVarName] : undefined;
  }

  // Returns a cooldown length in seconds if `error` looks like a
  // rate-limit/quota-exceeded response, or null if it's an ordinary failure
  // (timeout, DNS error, 5xx, etc.) - which still just returns null for this
  // one call, exactly as before this existed.
  private detectRateLimit(error: any): number | null {
    const status = error?.response?.status;
    if (status === 429) {
      const retryAfter = error?.response?.headers?.['retry-after'];
      if (retryAfter) {
        const asSeconds = parseFloat(retryAfter);
        if (!isNaN(asSeconds) && asSeconds > 0) return asSeconds;
        const asDate = Date.parse(retryAfter);
        if (!isNaN(asDate)) {
          const diff = (asDate - Date.now()) / 1000;
          if (diff > 0) return diff;
        }
      }
      return this.defaultRateLimitCooldownSeconds;
    }
    let bodyText = '';
    try { bodyText = JSON.stringify(error?.response?.data || '').toLowerCase(); } catch { /* ignore */ }
    const quotaPhrases = ['rate limit', 'too many requests', 'quota', 'exceeded', 'limit reached', 'over the limit', 'usage limit'];
    if (bodyText && quotaPhrases.some(p => bodyText.includes(p))) {
      return this.defaultRateLimitCooldownSeconds;
    }
    return null;
  }

  // Every Layer 1 HTTP call now goes through here instead of calling
  // this.httpClient.get directly: skips (zero network I/O) if the service
  // was disabled via IPCHECK_DISABLED_SERVICES or is currently cooling down
  // from a prior rate-limit response, otherwise performs the request and,
  // on failure, feeds the error through detectRateLimit to decide whether
  // to start a cooldown. Always resolves to null on any failure, same
  // fail-open contract every checkX method already had.
  private async safeGet(id: string, url: string, axiosConfig?: any): Promise<any | null> {
    if (!this.isServiceEnabled(id)) return null;
    if (this.cooldown.isOnCooldown(id)) return null;
    try {
      const r = await this.httpClient.get(url, axiosConfig);
      return r.data;
    } catch (e: any) {
      const cooldownSeconds = this.detectRateLimit(e);
      if (cooldownSeconds !== null) {
        this.cooldown.markRateLimited(id, cooldownSeconds);
      }
      return null;
    }
  }

  // ========================================================================
  // LAYER 1: REAL IP-INTELLIGENCE APIS
  // ========================================================================
  private async checkIpApi(ip: string): Promise<any> {
    const url = this.resolveUrl('ipapi', ip, (i) => `http://ip-api.com/json/${i}?fields=country,countryCode,city,isp,org,proxy,hosting,query`);
    const d = await this.safeGet('ipapi', url);
    return d?.isp ? { family: 'ipapi', country: d.country, city: d.city, isp: d.isp, org: d.org || d.isp, isProxy: d.proxy || false, proxyWeight: 2, isHosting: d.hosting || false, hostingWeight: 2 } : null;
  }
  private async checkIpwhois(ip: string): Promise<any> {
    const url = this.resolveUrl('ipwhois', ip, (i) => `https://ipwhois.app/json/${i}`);
    const d = await this.safeGet('ipwhois', url);
    return d?.isp ? { family: 'ipwhois', country: d.country, city: d.city, isp: d.isp, org: d.org || d.isp, isVpn: d.type === 'VPN', vpnWeight: 2, isProxy: d.type === 'Proxy', proxyWeight: 2, isHosting: d.type === 'Hosting', hostingWeight: 2 } : null;
  }
  private async checkIpapiCo(ip: string): Promise<any> {
    const url = this.resolveUrl('ipapico', ip, (i) => `https://ipapi.co/${i}/json/`);
    const d = await this.safeGet('ipapico', url);
    return d?.org ? { family: 'ipapico', country: d.country_name, city: d.city, isp: d.org, org: d.org, isHosting: d.asn?.type === 'hosting', hostingWeight: 1 } : null;
  }
  // v8.3 - ipinfo.io's paid-tier auth param is `?token=`, appended only when
  // a key is configured (via apis.ipinfo_api.api_key or IPINFO_API_KEY) -
  // same "optional in both directions" pattern as proxycheck: works keyless
  // for light use, and a configured token just raises the quota/detail.
  private async checkIpinfo(ip: string): Promise<any> {
    const key = this.resolveApiKey('ipinfo', 'IPINFO_API_KEY');
    const url = this.resolveUrl('ipinfo', ip, (i) => `https://ipinfo.io/${i}/json${key ? `?token=${key}` : ''}`, key);
    const d = await this.safeGet('ipinfo', url);
    return d?.org ? { family: 'ipinfo', country: d.country, city: d.city, isp: d.org, org: d.org, isVpn: d.privacy?.vpn || false, vpnWeight: 2, isProxy: d.privacy?.proxy || false, proxyWeight: 2, isTor: d.privacy?.tor || false, torWeight: 3, isHosting: d.privacy?.hosting || false, hostingWeight: 2 } : null;
  }
  private async checkVpnApi(ip: string): Promise<any> {
    const key = this.resolveApiKey('vpnapi', 'VPNAPI_KEY');
    if (!key) return null;
    const url = this.resolveUrl('vpnapi', ip, (i) => `https://vpnapi.io/api/${i}?key=${key}`, key);
    const d = await this.safeGet('vpnapi', url);
    if (!d) return null;
    const s = d?.security || {};
    const n = d?.network || {};
    return { family: 'vpnapi', country: d?.location?.country, city: d?.location?.city, isp: n.isp || '', org: n.organization || '', isVpn: s.vpn || false, vpnWeight: 3, isProxy: s.proxy || false, proxyWeight: 3, isTor: s.tor || false, torWeight: 3, isHosting: s.relay || false, hostingWeight: 2 };
  }
  // v8.2: upgraded from the v2 endpoint to v3. Still works keyless (same as
  // before), and automatically uses PROXYCHECK_API_KEY for a higher quota
  // when it's set - "optional" in both directions.
  private async checkProxyCheck(ip: string): Promise<any> {
    const key = this.resolveApiKey('proxycheck', 'PROXYCHECK_API_KEY');
    const url = this.resolveUrl('proxycheck', ip, (i) => `https://proxycheck.io/v3/${i}?vpn=1&asn=1&risk=1${key ? `&key=${key}` : ''}`, key);
    const data = await this.safeGet('proxycheck', url);
    if (!data) return null;
    const d = data?.[ip] || {};
    return { family: 'proxycheck', country: d?.country || 'Unknown', city: d?.city || 'Unknown', isp: d?.provider || '', org: d?.provider || '', isVpn: d?.proxy === 'yes' || d?.vpn === 'yes', vpnWeight: 3, isProxy: d?.proxy === 'yes', proxyWeight: 3, isTor: d?.type === 'Tor', torWeight: 3, isHosting: d?.type === 'Data Center', hostingWeight: 2 };
  }
  private async checkIPQuality(ip: string): Promise<any> {
    const key = this.resolveApiKey('ipquality', 'IPQUALITY_KEY');
    if (!key) return null;
    const url = this.resolveUrl('ipquality', ip, (i) => `https://www.ipqualityscore.com/api/json/ip/${key}/${i}?strictness=1`, key);
    const d = await this.safeGet('ipquality', url);
    if (!d) return null;
    return { family: 'ipquality', country: d?.country_code, city: d?.city, isp: d?.ISP || '', org: d?.organization || '', isVpn: d?.vpn || d?.active_vpn || false, vpnWeight: 2, isProxy: d?.proxy || d?.active_proxy || false, proxyWeight: 2, isTor: d?.tor || d?.active_tor || false, torWeight: 2, isDatacenter: d?.is_data_center || false, datacenterWeight: 2 };
  }
  private async checkAbuseIPDB(ip: string): Promise<any> {
    const key = this.resolveApiKey('abuseipdb', 'ABUSEIPDB_KEY');
    if (!key) return null;
    const url = this.resolveUrl('abuseipdb', ip, (i) => `https://api.abuseipdb.com/api/v2/check?ipAddress=${i}`);
    const data = await this.safeGet('abuseipdb', url, { timeout: 3000, headers: { 'Key': key, 'Accept': 'application/json' } });
    if (!data) return null;
    const d = data?.data;
    // Only use AbuseIPDB's own usageType classification (hosting/datacenter),
    // never its abuse-confidence score - a high abuse score reflects past
    // reports against the IP (which may now belong to a different,
    // innocent customer), not VPN/proxy usage.
    return { family: 'abuseipdb', country: d?.countryCode, city: '', isp: d?.isp || '', org: d?.domain || '', isHosting: (d?.usageType || '').includes('Data Center') || (d?.usageType || '').includes('Hosting'), hostingWeight: 2 };
  }
  // v8.0: delegates to ReverseDnsService (see that file) instead of calling
  // dns.reverse directly, so this and the dedicated Layer 2.5 reverse-DNS
  // lookup share one cache and one in-flight-dedup map - a connection that
  // reaches Layer 2.5 after this battery already ran gets an instant cache
  // hit instead of a second DNS round trip.
  //
  // FP-hardening (v8.4): marked `weak`. A PTR hostname substring is a
  // DERIVED inference, not a purpose-built detection service's verdict -
  // an ordinary residential gateway named "dsl-tunnel-gw3.isp.net" matches
  // 'tunnel', and letting that count as a confirming *source* meant PTR +
  // one single mistaken API could clear the 2-source permanent-ban bar by
  // themselves. As a weak signal it still contributes its full vpnScore
  // weight (detection unchanged - the score thresholds still see it) and
  // still feeds the composite engine's badReverseDns signal via Layer 2.5,
  // but the *Sources corroboration count now only ever reflects real,
  // independent detection services. It also no longer exports the hostname
  // as isp/org, which used to poison the trusted-provider and brand-
  // keyword checks with hostname text.
  private async checkReverseDNS(ip: string): Promise<any> {
    const result = await this.reverseDnsService.lookup(ip);
    if (!result.hostname) return null;
    const lower = result.hostname.toLowerCase();
    return {
      weak: true, family: 'rdns',
      isVpn: ['vpn', 'proxy', 'tor-exit', 'tunnel'].some(k => lower.includes(k)), vpnWeight: 1,
    };
  }

  // ========================================================================
  // NEW REAL SIGNALS (v6.0)
  // ========================================================================

  // Purpose-built VPN/proxy/datacenter detection service. Free tier works
  // without a key for light traffic; gracefully no-ops if rate-limited.
  private async checkIpapiIs(ip: string): Promise<any> {
    const url = this.resolveUrl('ipapiis', ip, (i) => `https://api.ipapi.is/?q=${i}`);
    const d = await this.safeGet('ipapiis', url);
    const companyName = d?.company?.name || d?.asn?.org || '';
    return d && typeof d.is_datacenter !== 'undefined' ? {
      family: 'ipapiis',
      country: d?.location?.country, city: d?.location?.city,
      isp: companyName, org: companyName,
      isVpn: !!d.is_vpn, vpnWeight: 2,
      isProxy: !!d.is_proxy, proxyWeight: 2,
      isTor: !!d.is_tor, torWeight: 2,
      isHosting: !!d.is_datacenter, hostingWeight: 2,
      isDatacenter: !!d.is_datacenter, datacenterWeight: 2,
    } : null;
  }

  // iplocate.io - purpose-built VPN/proxy/hosting/Tor detection, same
  // "optional" pattern as vpnapi/ipquality/abuseipdb/getipintel: no-ops
  // unless IPLOCATE_API_KEY is set.
  private async checkIplocate(ip: string): Promise<any> {
    const key = this.resolveApiKey('iplocate', 'IPLOCATE_API_KEY');
    if (!key) return null;
    const url = this.resolveUrl('iplocate', ip, (i) => `https://iplocate.io/api/lookup/${i}?apikey=${key}`, key);
    const d = await this.safeGet('iplocate', url);
    if (!d) return null;
    const p = d?.privacy || {};
    const isp = d?.asn?.name || d?.org || '';
    return {
      family: 'iplocate',
      country: d?.country, city: d?.city, isp, org: isp,
      isVpn: !!p.is_vpn, vpnWeight: 2,
      isProxy: !!p.is_proxy, proxyWeight: 2,
      isTor: !!p.is_tor, torWeight: 3,
      isHosting: !!p.is_hosting || !!p.is_datacenter, hostingWeight: 2,
      isDatacenter: !!p.is_datacenter, datacenterWeight: 2,
    };
  }

  // ipregistry.co - purpose-built VPN/proxy/relay/cloud-provider detection,
  // same "optional" pattern: no-ops unless IPREGISTRY_API_KEY is set.
  private async checkIpregistry(ip: string): Promise<any> {
    const key = this.resolveApiKey('ipregistry', 'IPREGISTRY_API_KEY');
    if (!key) return null;
    const url = this.resolveUrl('ipregistry', ip, (i) => `https://api.ipregistry.co/${i}?key=${key}`, key);
    const d = await this.safeGet('ipregistry', url);
    if (!d) return null;
    const sec = d?.security || {};
    const conn = d?.connection || {};
    const isp = conn?.organization || '';
    return {
      family: 'ipregistry',
      country: d?.location?.country?.name, city: d?.location?.city, isp, org: isp,
      isVpn: !!sec.is_vpn, vpnWeight: 2,
      isProxy: !!sec.is_proxy || !!sec.is_anonymous, proxyWeight: 2,
      isTor: !!sec.is_tor, torWeight: 3,
      isHosting: !!sec.is_cloud_provider || conn?.type === 'hosting', hostingWeight: 2,
      isDatacenter: !!sec.is_cloud_provider, datacenterWeight: 2,
    };
  }

  // Live api.iptoasn.com lookup used to live here. It's now redundant and
  // removed: AsnIndex (see that file) already answers the exact same
  // question - "which ASN announces this IP" - from a locally-held table
  // with zero network round trip, checked as Layer 0.5 before any of these
  // API calls even fire. See checkIpInternal's Layer 0.5 block.

  // getipintel.net - a purpose-built VPN/proxy probability scoring service,
  // free with a contact-email query parameter (no API key). No-ops unless
  // GETIPINTEL_EMAIL is configured, same pattern as the other optional
  // key-gated sources in this file. A conservative 0.90 probability bar is
  // used so only a strong verdict counts as one corroborating source.
  private async checkGetIpIntel(ip: string): Promise<any> {
    const email = this.resolveApiKey('getipintel', 'GETIPINTEL_EMAIL');
    if (!email) return null;
    const url = this.resolveUrl('getipintel', ip, (i) => `https://check.getipintel.net/check.php?ip=${i}&contact=${encodeURIComponent(email)}&format=json`);
    const d = await this.safeGet('getipintel', url);
    if (!d) return null;
    const score = parseFloat(d?.result);
    if (isNaN(score) || score < 0) return null; // negative = rate-limited/error code, not a verdict
    return score >= 0.90 ? { family: 'getipintel', isProxy: true, proxyWeight: 2, isVpn: true, vpnWeight: 1 } : null;
  }

  // RDAP (the modern, structured successor to WHOIS) - authoritative
  // registry data straight from the RIR. Used only to extract the
  // network/org name and run it through the exact same brand-name keyword
  // lists as everything else.
  //
  // FP-hardening (v8.4): marked `weak`, same rationale as checkReverseDNS -
  // a keyword match against a registry org-name string is a derived
  // inference, not an independent detection service's verdict, so it
  // contributes score but never a confirming source, and its text no
  // longer overwrites isp/org (a registry allocation name like
  // "EXAMPLE-HOSTING-NET" is not what the player's ISP calls itself, and
  // it used to both trigger AND mask the keyword/trusted-provider layers).
  private async checkRdap(ip: string): Promise<any> {
    const url = this.resolveUrl('rdap', ip, (i) => `https://rdap.org/ip/${i}`);
    const d = await this.safeGet('rdap', url);
    if (!d) return null;
    const name = d?.name || '';
    const entities = Array.isArray(d?.entities) ? d.entities : [];
    const orgFromVcard = entities
      .flatMap((e: any) => (Array.isArray(e?.vcardArray?.[1]) ? e.vcardArray[1] : []))
      .find((f: any) => Array.isArray(f) && f[0] === 'fn')?.[3] || '';
    const text = `${name} ${orgFromVcard}`.trim();
    if (!text) return null;
    const normalized = this.normalizeProviderText(text);
    const isVpn = this.matchesKeywords(normalized, VPN_KEYWORDS_NORMALIZED);
    const isProxy = this.matchesKeywords(normalized, PROXY_KEYWORDS_NORMALIZED);
    const isHosting = this.matchesKeywords(normalized, HOSTING_KEYWORDS_NORMALIZED) || this.matchesKeywords(normalized, DATACENTER_KEYWORDS_NORMALIZED);
    return {
      weak: true, family: 'rdap',
      isVpn, vpnWeight: 1, isProxy, proxyWeight: 1, isHosting, hostingWeight: 1,
    };
  }

  // Shaped like the other check* methods so it flows through the same
  // scoring loop. Reads from the in-memory cache (see refreshTorExitList)
  // instead of making a network call per player.
  private async checkTorMembership(ip: string): Promise<any> {
    const set = await this.getTorExitSet();
    return set.has(ip) ? { family: 'torproject', isTor: true, torWeight: 3 } : null;
  }

  // ========================================================================
  // OFFICIAL TOR PROJECT EXIT LIST (cached, background-refreshed)
  // ========================================================================
  private async getTorExitSet(): Promise<Set<string>> {
    const isStale = Date.now() - this.torExitLoadedAt > this.torExitRefreshMs;
    if (this.torExitSet.size === 0 && isStale) {
      // Nothing loaded yet at all - block just this once so the very first
      // checks still get Tor coverage instead of silently skipping it.
      await this.refreshTorExitList();
    } else if (isStale && !this.torExitRefreshing) {
      // Already have a (slightly stale) list - refresh in the background
      // without making this or any other in-flight check wait on it.
      this.refreshTorExitList().catch(() => {});
    }
    return this.torExitSet;
  }

  private async refreshTorExitList(): Promise<void> {
    if (this.torExitRefreshing) return this.torExitRefreshing;
    this.torExitRefreshing = (async () => {
      try {
        const r = await this.httpClient.get(`https://check.torproject.org/torbulkexitlist`, { timeout: 8000 });
        const lines: string[] = (r.data || '').split('\n').map((l: string) => l.trim()).filter(Boolean);
        this.torExitSet = new Set(lines);
        this.torExitLoadedAt = Date.now();
        this.logger.debug(`Tor exit list refreshed: ${this.torExitSet.size} nodes`);
      } catch (e) {
        this.logger.warn('Failed to refresh Tor exit list, keeping previous cache');
      } finally {
        this.torExitRefreshing = null;
      }
    })();
    return this.torExitRefreshing;
  }

  // ========================================================================
  // HELPERS
  // ========================================================================
  // Fire-and-forget reputation bookkeeping (requirements #1, #6) - folds
  // this observation into both the per-IP and per-subnet reputation
  // stores. Both stores are pure in-memory Map updates with debounced disk
  // persistence (see NetworkReputationStore/IpReputationStore), so this
  // never adds meaningful latency to the connection it's called from and
  // never needs to be awaited.
  private recordReputationObservation(ip: string, banned: boolean, vpnDetection: boolean, riskScore: number): void {
    try {
      this.ipReputationStore.recordObservation(ip, { banned, vpnDetection, riskScore });
      this.networkReputationStore.recordObservation(ip, { banned, vpnDetection, riskScore });
    } catch (e) {
      // Reputation bookkeeping must never be able to affect the actual
      // join decision it's called alongside - swallow and log only.
      this.logger.debug(`Reputation bookkeeping failed for ${ip}: ${e}`);
    }
  }

  // `keywords` must already be pre-normalized (see the *_NORMALIZED
  // exports in ProviderLists.ts) - normalizing here, per keyword, on every
  // single call would redo the same fixed string transform hundreds of
  // times per player connection for no benefit, since the keyword lists
  // never change at runtime.
  private matchesKeywords(text: string, keywords: string[]): boolean {
    for (const kw of keywords) {
      if (text.includes(kw)) return true;
    }
    return false;
  }
  private isTrustedProvider(text: string): boolean {
    const n = this.normalizeProviderText(text);
    for (const t of TRUSTED_PROVIDERS_NORMALIZED) {
      if (n.includes(t)) return true;
    }
    return false;
  }
  private normalizeProviderText(text: string): string {
    return (text || '').toLowerCase().replace(/[^a-z0-9]+/gi, ' ').replace(/\s+/g, ' ').trim();
  }
  // FP-hardening: category booleans now default to FALSE and each ban path
  // sets only the categories it has actually proven (or leaves them all false
  // for reason-only bans like operator blacklist / weighted composite). This
  // stops every ban being reported downstream (reputation stores, ML training,
  // webhooks) as "vpn+proxy+hosting+datacenter" when it proved none of them -
  // the mislabel that let composite/dataset bans snowball innocent neighbours'
  // subnet reputation. `confidence` (default 'soft' = quarantine + review)
  // drives permanent-vs-quarantine in PlayerTracker.autoBan.
  private createBanResult(ip: string, country: string, city: string, isp: string, org: string, score: number, confidence: 'hard' | 'soft' = 'soft'): IpCheckResult {
    return { ip, verdict: 'ban', is_vpn: false, is_proxy: false, is_hosting: false, is_tor: false, is_datacenter: false, country, city, isp, organization: org, risk_score: score, threat_level: 'critical', ban_confidence: confidence, checked_at: new Date().toISOString(), cached: false };
  }
  private createCleanResult(ip: string, country: string, city: string, isp: string, org: string): IpCheckResult {
    return { ip, verdict: 'clean', is_vpn: false, is_proxy: false, is_hosting: false, is_tor: false, is_datacenter: false, country, city, isp, organization: org, risk_score: 0, threat_level: 'low', checked_at: new Date().toISOString(), cached: false };
  }
  getStats() {
    return {
      cache_size: this.cache.size(),
      asn_index: this.asnIndex.getStats(),
      asn_verdict_cache_size: this.asnVerdictCache.size,
      ml: this.mlDetector.getStats(),
      network_reputation: this.networkReputationStore.getStats(),
      ip_reputation: this.ipReputationStore.getStats(),
      reverse_dns: this.reverseDnsService.getStats(),
      network_age: this.networkAgeService.getStats(),
      residential_proxy: this.residentialProxyDetector.getStats(),
      datasets: this.datasetLoader.getStats(),
      rate_limit_cooldowns: this.cooldown.getStats(),
    };
  }
}