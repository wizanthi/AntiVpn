// IP check result from various detection methods
export interface IpCheckResult {
  ip: string;
  is_vpn: boolean;
  is_proxy: boolean;
  is_hosting: boolean;
  is_tor: boolean;
  is_datacenter: boolean;
  country?: string;
  city?: string;
  isp?: string;
  organization?: string;
  risk_score?: number;
  threat_level?: 'low' | 'medium' | 'high' | 'critical';
  checked_at: string;
  cached?: boolean;
  // --- v8.0 reputation-scoring enrichment (see RiskScoringEngine) ---
  // Purely additive/optional so any existing consumer of IpCheckResult
  // (webhooks, dashboards, etc.) keeps working unchanged if it ignores
  // these fields.
  risk_level?: RiskLevel;
  risk_breakdown?: ScoreBreakdownEntry[];
  // Offline ASN-index attribution for this IP (BGP fact, zero-latency
  // lookup). asn_country is the index's ISO-2 country - used by
  // PlayerTracker's impossible-travel check as a second, independent geo
  // source so a single wrong API country can't fabricate a travel jump.
  asn?: number;
  asn_country?: string;
  subnet_reputation_score?: number;
  ip_reputation_score?: number;
  residential_proxy_score?: number;
  network_age_days?: number | null;
  reverse_dns_hostname?: string | null;
  // v8.1 - populated when a custom dataset (data/datasets) contributed to
  // this verdict, either as the instant-ban reason or as one line of the
  // weighted breakdown - see DatasetsConfig.mode.
  dataset_match?: DatasetMatch | null;
  // FP-hardening: how much confidence the ban carries, which decides
  // permanent-vs-quarantine in PlayerTracker.autoBan.
  //   'hard' - highest-confidence: operator blacklist/custom-ban, Tor, or a
  //            VPN/proxy category confirmed by 2+ independent sources. Gets a
  //            permanent ban + persistent blacklist entry.
  //   'soft' - single/weaker signal (offline ASN hit, keyword, ML, weighted
  //            composite, impossible-travel). Gets a time-boxed quarantine
  //            ban + a human-review webhook, and is NOT persistently
  //            blacklisted - so it can never become a permanent false ban.
  // Absent on clean results.
  ban_confidence?: 'hard' | 'soft';
  // FP-hardening: explicit verdict, so downstream consumers (PlayerTracker)
  // never have to INFER "was this a ban?" from side-channel fields like
  // threat_level or dataset_match - that inference is exactly what let
  // corroborate-mode dataset matches (attached to CLEAN results purely as
  // enrichment) get acted on as if they were bans. Set by createBanResult/
  // createCleanResult; may be absent on legacy cached entries persisted by
  // older versions, in which case consumers fall back to the old heuristic.
  verdict?: 'ban' | 'clean';
  // Set by PlayerTracker.applyTravelCheck when the impossible-travel
  // detector (a behavioral signal about the IDENTITY, not the IP) is what
  // flagged this result - the quarantine re-verification worker must not
  // treat "the IP itself re-checked clean" as refuting it, since a rotating
  // residential-proxy pool's IPs are clean by construction.
  travel_flagged?: boolean;
}

// Cached IP data with timestamp for TTL validation
export interface CachedIpData {
  result: IpCheckResult;
  timestamp: number;
  // Optional per-entry TTL override (ms) - set for SOFT-confidence results
  // so a quarantine verdict expires (and is fully re-checked) much sooner
  // than the global cache TTL. See CacheService.set.
  ttlMs?: number;
}

// Player tracking information
export interface TrackedPlayer {
  id: number;
  nickname: string;
  clan: string;
  ip: string;
  first_seen: string;
  last_seen: string;
  sessions: number;
  flags: PlayerFlags;
  ip_check?: IpCheckResult;
}

// Player status flags
export interface PlayerFlags {
  is_whitelisted: boolean;
  is_blacklisted: boolean;
  is_vpn: boolean;
  is_proxy: boolean;
  is_suspicious: boolean;
  is_trusted: boolean;
}

// Player info from server status
export interface StatusPlayer {
  id: number;
  score: number;
  latency: number;
  nickname: string;
  clan: string;
  ip: string;
}

// Server status response
export interface StatusResponse {
  players: StatusPlayer[];
  raw: string;
  timestamp: string;
}

// Alert payload for Discord webhooks
export interface AlertPayload {
  type: 'vpn_detected' | 'proxy_detected' | 'tor_detected' | 'hosting_detected' | 'blacklist_add' | 'error' | 'info' | 'reconnect' | 'startup';
  player?: {
    nickname: string;
    ip: string;
    id: number;
  };
  details?: Record<string, any>;
  timestamp: string;
  severity: 'info' | 'warning' | 'critical';
}

// Whitelist entry
export interface WhitelistEntry {
  ip: string;
  reason: string;
  added_at: string;
}

// Whitelist data structure
export interface WhitelistData {
  ips: string[];
  players: string[];
  providers: string[];
  auto_added: WhitelistEntry[];
}

// Blacklist entry
export interface BlacklistEntry {
  ip: string;
  player?: string;
  reason: string;
  added_at: string;
  detection_method: string;
}

// Blacklist data structure
export interface BlacklistData {
  ips: string[];
  players: string[];
  auto_added: BlacklistEntry[];
}

// Application configuration
export interface AppConfig {
  server: {
    host: string;
    port: number;
    password?: string;
    rcon_password: string;
    rcon_username?: string;
  };
  discord: {
    webhook_url: string;
    alert_webhook_url: string;
  };
  ipcheck: {
    rate_limit_ms: number;
    cache_ttl_hours: number;
    retry_attempts: number;
    retry_delay_ms: number;
    // Bounded LRU size for the per-IP verdict cache (CacheService) - the
    // hot-path "IP -> small LRU cache -> ... -> return" front door. Default
    // 5000 if omitted (see ConfigManager). Millions of distinct player IPs
    // must never grow this cache unbounded.
    cache_max_entries?: number;
  };
  monitoring: {
    status_interval_seconds: number;
    reconnect_delay_ms: number;
    max_reconnect_attempts: number;
    hourly_reconnect: boolean;
    reconnect_interval_minutes: number;
  };
  logs: {
    cleanup_interval_hours: number;
    max_age_days: number;
    keep_only_today: boolean;
  };
  bot: {
    nickname: string;
    clan: string;
  };
  // In-game admin command access (see AdminCommandService.ts). Only players
  // whose join IP is listed in whitelisted_ips may use `$sudo antivpn ...`
  // commands from chat / whispers. Optional - if omitted, no IP is
  // whitelisted and every command attempt is denied.
  admin?: {
    prefix?: string;          // default '$'
    whitelisted_ips?: string[];
  };
  // Master switch, toggled at runtime by `$sudo antivpn enable 1/0` and
  // persisted to config.json so it survives rejoins AND full restarts.
  // When enabled=false the bot still connects, keeps its hourly reconnect
  // and answers admin commands - it just never checks or bans anyone.
  // Optional; omitted means enabled.
  antivpn?: {
    enabled?: boolean;        // default true
  };
  auto_ban: {
    enabled: boolean;
    mode: 'warn' | 'autoban';
    ban_duration_minutes: number;
    // Reason string passed to the RCON `ban` command (was previously
    // hardcoded in PlayerTracker). Optional for backward compatibility.
    ban_reason?: string;
    // Quarantine/review safety net for SOFT-confidence detections (see
    // IpCheckResult.ban_confidence). When enabled (default), a soft detection
    // is time-boxed to `duration_minutes` and routed to a review webhook
    // instead of receiving a permanent ban + blacklist entry.
    quarantine?: {
      enabled?: boolean;          // default true
      duration_minutes?: number;  // default 60
      review_webhook?: boolean;   // default true - post a review alert
      // FP-hardening: automatic re-verification of every soft quarantine
      // (see QuarantineReviewer.ts). After `review_after_minutes` the IP is
      // re-checked with the FULL detection pipeline (cache bypassed, no
      // single-signal soft short-circuits): a hard-confirmed result
      // escalates the quarantine to a permanent ban, a fully-clean result
      // auto-unbans ("FP averted"), a soft-again result leaves the
      // time-boxed quarantine exactly as it was. Detection is never
      // reduced - real offenders get UPGRADED to permanent, only verdicts
      // the full pipeline itself no longer stands behind are reverted.
      auto_review?: boolean;        // default true
      review_after_minutes?: number; // default 6
    };
  };
  impossible_travel?: {
    enabled: boolean;
    use_soft_match: boolean;
  };
  // Optional - if omitted, DEFAULT_DETECTION_CONFIG (see
  // config/DetectionDefaults.ts) is deep-merged in by ConfigManager so
  // every existing config.json still loads without modification.
  detection?: DetectionConfig;
  // Optional - see config/DatasetsDefaults.ts / DatasetLoader.ts (v8.1).
  datasets?: DatasetsConfig;
  // Optional - see config/ApisDefaults.ts / IpChecker.ts (v8.3). Per-service
  // enable toggle and API key/credential for the Layer 1 IP-intelligence
  // APIs, deep-merged against DEFAULT_APIS_CONFIG by ConfigManager.
  apis?: ApisConfig;
  // Optional - see config/StorageDefaults.ts / StorageAdapter.ts. Where the
  // small operator-managed stores (blacklist, whitelist, custombans, IP/
  // network reputation, the checked-IP cache) persist. Defaults to the
  // existing data/*.json files if omitted.
  storage?: StorageConfig;
}

// ============================================================================
// STORAGE BACKEND (optional DB-backed persistence for blacklist/whitelist/
// custombans/ip_reputation/network_reputation/checked_ips)
// ============================================================================
// These stores are small, operator-managed documents (not the multi-million-
// entry curated bulk lists/datasets/ASN table - those are handled by
// RangeIndexStore.ts, which honors this same `type` choice: 'mysql' moves
// them into that database too, in their own antivpn_range_* tables; 'file'
// and 'sqlite' both fall back to RangeIndexStore's dedicated SQLite file,
// since a per-JSON-document store was never a fit for them either way).
// By default these small stores are read/written as data/*.json files,
// same as always; setting `type` to 'sqlite' or 'mysql' moves them into a
// single `antivpn_store` table in that database instead - see
// StorageAdapter.ts.
export interface StorageConfig {
  type: 'file' | 'sqlite' | 'mysql';
  sqlite: {
    // Relative to the project root (process.cwd()), same convention as
    // every other data/* path in this project.
    path: string;
  };
  mysql: {
    host: string;
    port: number;
    user: string;
    password: string;
    database: string;
    connection_limit?: number;
  };
}

// ============================================================================
// LAYER 1 IP-INTELLIGENCE API CONFIG (v8.3)
// ============================================================================
// Per-service config.json override for the API battery in IpChecker.ts. If
// `api_key` is left empty, that service falls back to its existing env var
// (e.g. PROXYCHECK_API_KEY) if set, else runs keyless (if the service
// supports that) or is skipped entirely. `enabled: false` turns a service
// off from config.json directly, in addition to the existing
// IPCHECK_DISABLED_SERVICES env var - see IpChecker.ts's isServiceEnabled().
export interface ApiServiceConfig {
  enabled: boolean;
  // Also holds getipintel_api's contact email, since that's the credential
  // that service uses instead of a key.
  api_key?: string;
}
export type ApisConfig = Record<string, ApiServiceConfig>;

// ============================================================================
// CUSTOM DATASETS (v8.1) - data/datasets loader
// ============================================================================
// Lets an operator drop their own IP/CIDR/ASN block-list data (txt, netset,
// ipset, cidr, csv, tsv, json, mmdb, parquet, bin, or any of those zipped
// up, in any folder structure) into data/datasets and have it enforced the
// same way the existing curated bulk lists already are - see
// DatasetLoader.ts for the full format-by-format breakdown.
export type DatasetMatchType = 'ip' | 'cidr' | 'asn' | 'mmdb';

export interface DatasetMatch {
  source: string; // dataset file/entry name the match came from
  type: DatasetMatchType;
  value: string; // the specific IP/CIDR/ASN that matched
}

export interface DatasetsConfig {
  enabled: boolean;
  // Relative to the project root (process.cwd()), same convention as every
  // other data/* path in this project.
  directory: string;
  // 'instant'  - a match bans immediately, the same trust level already
  //              given to VERIFIED_HOSTING_VPN_ASNS / the ListUpdater bulk
  //              lists (this is curated data the operator deliberately
  //              added, not a guess).
  // 'corroborate' - a match only ever contributes the `dataset_match`
  //              weight to RiskScoringEngine, for operators who'd rather
  //              treat their own datasets with the same multi-signal
  //              caution as the rest of the reputation engine.
  mode: 'instant' | 'corroborate';
  // 0 disables periodic re-scanning; otherwise the folder is re-loaded on
  // this cadence so an operator can drop in/update files without a
  // restart. The very first load always happens once at startup.
  reload_interval_minutes: number;
  // Safety cap - a single file larger than this is skipped (logged as a
  // warning) rather than risking memory exhaustion from an accidental
  // multi-GB drop-in.
  max_file_size_mb: number;
  // How many levels of zip-within-zip to follow before giving up - guards
  // against zip-bomb-style nesting.
  max_zip_depth: number;
  // Path prefixes (relative to `directory`, forward-slash separated) to
  // skip entirely during the walk - for pre-existing bulk downloads that
  // include files outside the IP/ASN block-list intent (e.g. per-country
  // netset partitions of the entire internet, which would instant-ban
  // whole countries in 'instant' mode rather than flag actual abuse).
  exclude: string[];
  // ISO-2 country codes (e.g. ["RU"]) whose players are exempt from the
  // DATASET checks only - a player whose IP's ASN-index country matches is
  // never dataset-banned ('instant') and never gets the dataset_match
  // composite signal ('corroborate'). Every other layer (API battery,
  // verified-hosting ASNs, keywords, Tor, ML, composite) still applies to
  // them in full. Country comes from the offline ASN index (iptoasn.com's
  // country_code column) - zero latency, no extra network call. An IP the
  // index can't attribute a country to is treated as NOT excluded.
  exclude_countries: string[];
}

// ============================================================================
// REPUTATION-BASED SCORING (v8.0)
// ============================================================================
// Everything below backs the weighted risk-scoring engine, CIDR/IP
// reputation stores, reverse-DNS detector, network-age lookup and
// residential-proxy detector. All of it is additive: none of the existing
// types/fields above were changed, only extended.

export type RiskLevel = 'safe' | 'suspicious' | 'high_risk' | 'critical';

// One line of a score breakdown, e.g. { label: 'Hosting ASN', weight: 30 }
// renders as "+30 Hosting ASN" in logs - see RiskScoringEngine.
export interface ScoreBreakdownEntry {
  label: string;
  weight: number;
}

export interface RiskAssessment {
  score: number;
  level: RiskLevel;
  breakdown: ScoreBreakdownEntry[];
  // Count of distinct weighted categories that fired - used to enforce
  // "never act on a single signal" (see requirement #9 in the brief).
  independentSignals: number;
}

// Per-signal point values for the weighted scoring engine. All
// configurable at runtime via config.json -> detection.weights.
export interface RiskWeightsConfig {
  known_vpn_api: number;
  hosting_asn: number;
  residential_proxy: number;
  tor: number;
  bad_reverse_dns: number;
  ip_reputation: number;
  cidr_reputation: number;
  // The existing MlDetector already outputs a 0-100 score; this multiplier
  // scales that into the same point system as everything else above (e.g.
  // a multiplier of 0.3 turns an ML score of 100 into +30 points).
  ml_score_multiplier: number;
  // v8.1 - only used when datasets.mode = 'corroborate' (see DatasetLoader);
  // in the default 'instant' mode a dataset hit bans directly, same as the
  // existing curated bulk lists / VERIFIED_HOSTING_VPN_ASNS, and this
  // weight is unused.
  dataset_match: number;
  // FP-hardening: per-entry-type dataset weights. A single-IP dataset entry
  // is the most specific claim a list can make; a CIDR is broader; an ASN
  // entry covers an entire network operator (potentially millions of
  // customers of a mislisted residential ISP) and is therefore the most
  // false-positive-prone kind of entry by construction. Optional - each
  // falls back to `dataset_match` (ip), or a scaled-down fraction of it
  // (cidr/asn), when unset. See RiskScoringEngine.datasetWeightFor.
  dataset_match_ip?: number;
  dataset_match_cidr?: number;
  dataset_match_asn?: number;
}

// Risk-level boundaries (inclusive upper bounds). Anything above
// high_risk_max is 'critical'. Configurable without recompiling.
export interface RiskThresholdsConfig {
  safe_max: number;
  suspicious_max: number;
  high_risk_max: number;
}

export interface CidrReputationConfig {
  enabled: boolean;
  ipv4_prefix: number; // 24 = /24
  ipv6_prefix: number; // 48 = /48
  // A subnet needs at least this many observed distinct IPs before its
  // reputation counts for anything - avoids a single unlucky IP skewing a
  // near-empty subnet's score.
  min_samples_for_score: number;
  cache_ttl_minutes: number;
}

export interface ReverseDnsConfig {
  enabled: boolean;
  keywords: string[];
  cache_ttl_minutes: number;
  timeout_ms: number;
}

export interface NetworkAgeConfig {
  enabled: boolean;
  // Networks allocated more recently than this are treated as "recent".
  young_network_days: number;
  cache_ttl_hours: number;
  timeout_ms: number;
}

export interface ResidentialProxyWeights {
  api_signal: number;
  network_type: number;
  asn_reputation: number;
  org_reputation: number;
  historical_ip_reputation: number;
  cidr_reputation: number;
  reverse_dns: number;
  ml_confidence: number;
}

export interface ResidentialProxyConfig {
  enabled: boolean;
  confidence_threshold: number; // 0-100
  cache_ttl_minutes: number;
  weights: ResidentialProxyWeights;
  // Never classify as a residential proxy on fewer than this many
  // independent agreeing signals (requirement #10).
  min_independent_signals: number;
}

export interface IpReputationConfig {
  enabled: boolean;
}

export interface DetectionConfig {
  weights: RiskWeightsConfig;
  thresholds: RiskThresholdsConfig;
  // Minimum number of independent weighted categories required before the
  // NEW composite/weighted-score path (Layer 3.75 in IpChecker) is allowed
  // to add an IP to the blacklist on its own - see requirement #9.
  min_independent_signals_for_ban: number;
  cidr_reputation: CidrReputationConfig;
  reverse_dns: ReverseDnsConfig;
  network_age: NetworkAgeConfig;
  residential_proxy: ResidentialProxyConfig;
  ip_reputation: IpReputationConfig;
}

// --- Subnet (CIDR) reputation record - see NetworkReputationStore ---
export interface NetworkReputationRecord {
  subnet: string; // e.g. "1.2.3.0/24" or "2001:db8::/48"
  banned_ips: number;
  vpn_detections: number;
  unique_ips: number;
  risk_sum: number;
  risk_count: number;
  first_seen: string;
  last_updated: string;
}

// --- Per-IP historical reputation record - see IpReputationStore ---
export interface IpReputationRecord {
  ip: string;
  times_seen: number;
  times_banned: number;
  times_vpn_detected: number;
  risk_sum: number;
  risk_count: number;
  first_seen: string;
  last_seen: string;
}

// Queue task for processing
export interface QueueTask {
  id: string;
  type: 'ip_check' | 'webhook_alert' | 'rcon_command';
  data: any;
  priority: number;
  added_at: number;
  retries: number;
  max_retries: number;
}

// RCON authentication status
export interface RconAuthStatus {
  AuthLevel: number;
  ReceiveCommands: number;
}
