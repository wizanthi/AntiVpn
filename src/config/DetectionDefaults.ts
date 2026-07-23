// src/config/DetectionDefaults.ts
//
// Default values for every knob the new reputation/scoring engine exposes
// (weights, thresholds, per-detector enable flags, cache durations). These
// are deep-merged into whatever `detection` block (if any) exists in
// config.json by ConfigManager, so:
//   - An existing config.json with no `detection` key at all keeps working
//     exactly as before, picking up these defaults.
//   - An operator can override just the fields they care about (e.g. only
//     `detection.thresholds.high_risk_max`) without having to restate the
//     entire block.
import { DetectionConfig } from '../types';

export const DEFAULT_DETECTION_CONFIG: DetectionConfig = {
  // Point values for the weighted risk-scoring engine. Mirrors the example
  // in the project brief 1:1 so behavior out of the box matches spec.
  weights: {
    known_vpn_api: 20,
    hosting_asn: 30,
    residential_proxy: 25,
    tor: 60,
    bad_reverse_dns: 15,
    ip_reputation: 25,
    cidr_reputation: 20,
    ml_score_multiplier: 0.3, // ML score of 100 -> +30 points
    dataset_match: 30, // only used when datasets.mode = 'corroborate'
  },

  // 0-39 Safe | 40-69 Suspicious | 70-99 High Risk | 100+ Critical
  thresholds: {
    safe_max: 39,
    suspicious_max: 69,
    high_risk_max: 99,
  },

  // The new weighted-composite ban path (Layer 3.75 in IpChecker) never
  // fires on fewer than this many independently-weighted categories, no
  // matter how high the resulting score is - this is what keeps a single
  // noisy signal (e.g. only "Hosting ASN") from ever being enough on its
  // own, per requirement #9.
  min_independent_signals_for_ban: 3,

  cidr_reputation: {
    enabled: true,
    ipv4_prefix: 24,
    ipv6_prefix: 48,
    min_samples_for_score: 5,
    cache_ttl_minutes: 60,
  },

  reverse_dns: {
    enabled: true,
    // FP-hardening: 'cloud' and 'server' were removed - they routinely appear
    // in legitimate residential PTRs (e.g. "*.server.example-isp.net",
    // cloud-hosted mail relays) and produced a spurious reverse-DNS signal.
    keywords: ['vpn', 'proxy', 'colo', 'hosting', 'vps', 'exit', 'tor'],
    cache_ttl_minutes: 720, // 12h - PTR records rarely change more often than this
    timeout_ms: 2000,
  },

  network_age: {
    enabled: true,
    young_network_days: 180,
    cache_ttl_hours: 168, // 7d - allocation dates are effectively static
    timeout_ms: 2500,
  },

  residential_proxy: {
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
    // Never classify an IP as a residential proxy off a single signal.
    min_independent_signals: 2,
  },

  ip_reputation: {
    enabled: true,
  },
};

// Recursively fills in any missing keys of `override` from `defaults`,
// without mutating either input. Used by ConfigManager so a partial
// `detection` block in config.json only overrides what it specifies.
export function deepMergeDefaults<T>(defaults: T, override: Partial<T> | undefined | null): T {
  if (!override) return defaults;
  const result: any = Array.isArray(defaults) ? [...(defaults as any)] : { ...(defaults as any) };
  for (const key of Object.keys(override)) {
    // JSON.parse happily produces an object with an own "__proto__"/
    // "constructor"/"prototype" key (e.g. from a hand-edited or corrupted
    // config.json), and assigning into `result[key]` for one of those
    // would walk back up to the *actual* prototype chain rather than
    // setting a plain data property - skip them outright rather than
    // relying on every call site downstream to never trust an inherited
    // property it didn't expect.
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    const overrideVal = (override as any)[key];
    const defaultVal = (defaults as any)[key];
    if (
      overrideVal && typeof overrideVal === 'object' && !Array.isArray(overrideVal) &&
      defaultVal && typeof defaultVal === 'object' && !Array.isArray(defaultVal)
    ) {
      result[key] = deepMergeDefaults(defaultVal, overrideVal);
    } else if (overrideVal !== undefined) {
      result[key] = overrideVal;
    }
  }
  return result as T;
}
