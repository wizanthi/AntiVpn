// src/config/DatasetsDefaults.ts
//
// Default values for the data/datasets loader (see DatasetLoader.ts).
// Deep-merged into config.json's `datasets` block by ConfigManager, same
// pattern as DetectionDefaults.ts - an operator only has to specify the
// fields they want to change.
import { DatasetsConfig } from '../types';

export const DEFAULT_DATASETS_CONFIG: DatasetsConfig = {
  enabled: true,
  directory: 'data/datasets',
  // FP-hardening default: 'corroborate'. A dataset hit no longer bans on its
  // own - it only contributes the `dataset_match` weight to the composite
  // scoring engine, which still needs a high-risk score AND
  // min_independent_signals_for_ban distinct signals to act. This removes the
  // single biggest false-positive source (a lone hit in a noisy/abuse feed
  // that lists reassigned residential IPs). Set to 'instant' only if you
  // fully trust every file you drop in data/datasets to be VPN/proxy-specific.
  mode: 'corroborate',
  reload_interval_minutes: 60,
  max_file_size_mb: 1024,
  max_zip_depth: 3,
  // ISO-2 country codes exempt from the dataset checks ONLY (see
  // DatasetsConfig.exclude_countries). Russian residential IPs are heavily
  // over-represented in third-party abuse/proxy feeds (large CGNAT pools,
  // frequent reassignment), so dataset hits there are disproportionately
  // stale/false - every other detection layer (API battery, verified
  // hosting ASNs, keywords, Tor, ML, composite) still applies to these
  // players unchanged.
  exclude_countries: ['RU'],
  // See DatasetsConfig.exclude. Two categories excluded by default:
  //  - per-country CIDR partitions of the entire internet (geo-blocking
  //    data, not abuse data)
  //  - full IP-to-ASN/geo reference databases (MaxMind/DB-IP/IPinfo/
  //    IP2Location-style "map every routable IP to metadata" exports) -
  //    these cover the *entire* address space with no gaps, so loading
  //    them as instant-ban entries would ban the whole internet, not
  //    flag actual abuse.
  // Note: entries below with no "/" match by prefix against a top-level
  // file/folder *name* (see DatasetLoader.isExcluded), not just exact
  // equality - so "GeoLite2-ASN-CSV" still matches a re-downloaded,
  // differently-dated "GeoLite2-ASN-CSV_20260809" next month without
  // needing this list edited every refresh.
  exclude: [
    'blocklist-ipsets-master/geolite2_country',
    'blocklist-ipsets-master/ip2location_country',
    'blocklist-ipsets-master/ipdeny_country',
    'blocklist-ipsets-master/ipip_country',
    'prefix.csv',
    'ipinfo_lite.json',
    'IP2LOCATION-LITE-ASN.CSV',
    'GeoLite2-ASN-CSV',
    'ip2asn-v4.tsv',
    'dbip-asn-lite',
    // FP-hardening: abuse/attack/spam reputation feeds describe *past*
    // malware/abuse activity, not VPN/proxy infrastructure. They are the
    // worst offenders for listing since-reassigned residential IPs, so they
    // are excluded from the dataset index entirely (they would otherwise add
    // a misleading `dataset_match` signal to the composite score). Bare names
    // below match by basename prefix (see DatasetLoader.isExcluded), so the
    // dated/rolling variants (e.g. *_1d/_7d/_30d) are covered too.
    'abuseipdb',
    'blocklist_de',
    'bruteforceblocker',
    'dshield',
    'et_compromised',
    'et_dshield',
    'et_spamhaus',
    'feodo',
    'firehol_abusers',
    'firehol_level',
    'iblocklist_abuse',
    'iblocklist_cruzit',
    'iblocklist_spamhaus',
    'php_spammers',
    'spamhaus_drop',
    'spamhaus_edrop',
    'stopforumspam',
  ],
};
