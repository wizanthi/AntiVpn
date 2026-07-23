// src/services/RiskScoringEngine.ts
//
// Central weighted scoring engine - requirement #4.
//
// Replaces ad-hoc boolean "is this a ban" decisions with a single,
// transparent, additive score built from independently-weighted
// categories, mapped onto a configurable set of risk levels:
//   0-39   = Safe
//   40-69  = Suspicious
//   70-99  = High Risk
//   100+   = Critical
//
// This engine does not, by itself, decide anything - it only computes a
// score/level/breakdown from the inputs it's given and logs exactly how
// that number was reached (requirement #8). IpChecker.ts is still
// responsible for deciding what to DO with that score, and continues to
// enforce the project's existing "never act on a single signal" posture
// (see requirement #9) on top of this engine's output.
import { RiskAssessment, RiskLevel, RiskThresholdsConfig, RiskWeightsConfig, ScoreBreakdownEntry } from '../types';
import { Logger } from '../utils/Logger';

export interface RiskScoringInput {
  knownVpnApi: boolean;
  hostingAsn: boolean;
  residentialProxy: boolean;
  tor: boolean;
  badReverseDns: boolean;
  ipReputation: boolean;
  cidrReputation: boolean;
  mlScore: number; // 0-100, existing MlDetector output
  // v8.1 - only meaningful when datasets.mode = 'corroborate' (see
  // DatasetLoader); in the default 'instant' mode a dataset hit already
  // banned before RiskScoringEngine ever runs, so this stays false here.
  datasetMatch?: boolean;
  // FP-hardening: what KIND of dataset entry matched - drives the
  // per-entry-type weight split (an ASN entry is far broader, and far more
  // FP-prone, than a single-IP entry - see RiskWeightsConfig). Absent =
  // treated as 'ip' (full weight), preserving old behavior.
  datasetMatchType?: 'ip' | 'cidr' | 'asn' | 'mmdb';
  // Optional negative adjustment (e.g. a long, clean history for this
  // exact IP) - always <= 0, never enough on its own to offset a high
  // score from real positive signals, just a small tie-breaker.
  goodReputationBonus?: number;
}

export class RiskScoringEngine {
  constructor(
    private weights: RiskWeightsConfig,
    private thresholds: RiskThresholdsConfig,
    private logger: Logger,
  ) {}

  updateConfig(weights: RiskWeightsConfig, thresholds: RiskThresholdsConfig): void {
    this.weights = weights;
    this.thresholds = thresholds;
  }

  score(ip: string, input: RiskScoringInput): RiskAssessment {
    const breakdown: ScoreBreakdownEntry[] = [];
    let total = 0;
    let independentSignals = 0;

    const add = (flag: boolean, label: string, weight: number) => {
      if (flag && weight !== 0) {
        total += weight;
        breakdown.push({ label, weight });
        independentSignals++;
      }
    };

    add(input.knownVpnApi, 'Known VPN API', this.weights.known_vpn_api);
    add(input.hostingAsn, 'Hosting ASN', this.weights.hosting_asn);
    add(input.residentialProxy, 'Residential Proxy', this.weights.residential_proxy);
    add(input.tor, 'Tor', this.weights.tor);
    add(input.badReverseDns, 'Bad Reverse DNS', this.weights.bad_reverse_dns);
    add(input.ipReputation, 'IP Reputation', this.weights.ip_reputation);
    add(input.cidrReputation, 'CIDR Reputation', this.weights.cidr_reputation);
    if (input.datasetMatch) {
      const type = input.datasetMatchType || 'ip';
      add(true, `Custom Dataset (${type})`, this.datasetWeightFor(type));
    }

    if (input.mlScore > 0) {
      const mlContribution = Math.round(input.mlScore * this.weights.ml_score_multiplier);
      if (mlContribution !== 0) {
        total += mlContribution;
        breakdown.push({ label: 'Existing ML Score', weight: mlContribution });
        independentSignals++;
      }
    }

    if (input.goodReputationBonus) {
      total += input.goodReputationBonus;
      breakdown.push({ label: 'Good reputation', weight: input.goodReputationBonus });
    }

    total = Math.max(0, total);

    let level: RiskLevel;
    if (total <= this.thresholds.safe_max) level = 'safe';
    else if (total <= this.thresholds.suspicious_max) level = 'suspicious';
    else if (total <= this.thresholds.high_risk_max) level = 'high_risk';
    else level = 'critical';

    if (breakdown.length > 0) {
      const line = breakdown.map((b) => `${b.weight >= 0 ? '+' : ''}${b.weight} ${b.label}`).join(' ');
      this.logger.debug(`Risk score for ${ip}: ${line} | Final Score: ${total} (${level})`);
    }

    return { score: total, level, breakdown, independentSignals };
  }

  // FP-hardening: dataset weight by entry type. A single-IP entry is the
  // most specific claim (full weight); a CIDR/MMDB range is broader; an ASN
  // entry blankets an entire operator's address space and is the most
  // FP-prone kind of dataset line there is (one mislisted residential ISP
  // ASN = millions of innocent customers), so it contributes the least.
  // Operator-overridable per type; unset types scale off `dataset_match`
  // so an existing config.json keeps working with sane relative values.
  private datasetWeightFor(type: 'ip' | 'cidr' | 'asn' | 'mmdb'): number {
    const base = this.weights.dataset_match;
    switch (type) {
      case 'ip': return this.weights.dataset_match_ip ?? base;
      case 'cidr': return this.weights.dataset_match_cidr ?? Math.round(base * 2 / 3);
      case 'mmdb': return this.weights.dataset_match_cidr ?? Math.round(base * 2 / 3);
      case 'asn': return this.weights.dataset_match_asn ?? Math.round(base / 3);
    }
  }

  // Maps the new 4-tier risk level onto the existing IpCheckResult.threat_level
  // ('low'|'medium'|'high'|'critical') so nothing downstream (webhooks,
  // dashboards) needs to change to understand it.
  static toThreatLevel(level: RiskLevel): 'low' | 'medium' | 'high' | 'critical' {
    switch (level) {
      case 'safe': return 'low';
      case 'suspicious': return 'medium';
      case 'high_risk': return 'high';
      case 'critical': return 'critical';
    }
  }
}
