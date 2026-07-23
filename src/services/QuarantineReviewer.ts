// src/services/QuarantineReviewer.ts
//
// FP-hardening (v8.4): automatic re-verification of every SOFT quarantine.
//
// A soft quarantine is, by definition, a single-signal (or weak-composite)
// hypothesis: offline ASN hit, brand keyword, ML score, weighted composite,
// dataset ASN entry, impossible-travel. The quarantine itself already
// prevents the worst outcome (a permanent false ban), but before this
// worker existed the hypothesis was never re-tested - the player just sat
// banned for the quarantine window, and the cached soft verdict re-fired a
// fresh quarantine on every reconnect. In effect a wrong soft verdict WAS
// a permanent ban, delivered in 60-minute installments.
//
// This worker closes the loop. `review_after_minutes` (default 6) after a
// quarantine fires, the IP is re-checked with the FULL pipeline
// (IpChecker.recheckIp - cache dropped, whole API battery, all layers):
//
//   ESCALATE  - the re-check comes back a ban (hard OR soft): detection
//               stood up. A hard re-check upgrades the quarantine to the
//               operator's permanent ban duration; a soft re-check leaves
//               the existing time-boxed ban untouched (it will simply
//               expire, and the next connection re-evaluates - by then the
//               reviewer may have API corroboration). Either way the ML
//               model receives a positive training sample built from the
//               re-check - a resolved label, not a guess.
//
//   REVERT    - the re-check comes back CLEAN: the full pipeline itself no
//               longer stands behind the verdict. The RCON ban is lifted,
//               the cached verdict purged, and the ML model receives a
//               negative sample so the same weak pattern is less likely to
//               quarantine the next innocent player. A revert webhook makes
//               the "FP averted" visible to the operator.
//
// Exception: travel-flagged quarantines (result.travel_flagged) never
// auto-revert. Impossible-travel indicts the IDENTITY's movement pattern,
// not the IP - a rotating residential-proxy pool's IPs each re-check clean
// by construction, so "IP is clean" does not refute the travel evidence.
// They still escalate normally if the IP itself turns out dirty.
//
// Detection is never reduced by this worker: it can only UPGRADE a
// quarantine to permanent or leave it in place; the only thing it ever
// removes is a ban the full pipeline itself, given a second look and
// complete data, refuses to endorse.
import { IpCheckResult } from '../types';
import { Logger } from '../utils/Logger';
import { IpChecker } from './IpChecker';
import { WebhookService } from './WebhookService';
import { MlDetector } from './MlDetector';
import { ConfigManager } from '../config/ConfigManager';

export interface QuarantineCase {
  ip: string;
  nickname: string;
  banMinutes: number;
  result?: IpCheckResult; // the verdict that caused the quarantine
  bannedAt: number;       // epoch ms
}

interface ReviewerOptions {
  reviewAfterMinutes: number;
  onUnban?: (ip: string) => void; // lets PlayerTracker clear its bannedIps dedup set
}

export class QuarantineReviewer {
  private static instance: QuarantineReviewer | null = null;
  private logger: Logger;
  private rconService: any = null;
  private options: ReviewerOptions = { reviewAfterMinutes: 6 };
  private pending: Map<string, { case_: QuarantineCase; timer: NodeJS.Timeout }> = new Map();
  // FP telemetry - surfaced via getStats() and the periodic webhook summary.
  private stats = { reviewed: 0, escalated: 0, upheld: 0, reverted: 0 };

  private constructor() {
    this.logger = Logger.getInstance();
  }

  static getInstance(): QuarantineReviewer {
    if (!QuarantineReviewer.instance) QuarantineReviewer.instance = new QuarantineReviewer();
    return QuarantineReviewer.instance;
  }

  init(rconService: any, options: ReviewerOptions): void {
    this.rconService = rconService;
    this.options = options;
  }

  // One review per IP at a time - a reconnect-requeue while a review is
  // already scheduled just refreshes the case data, not the timer (the
  // earlier-scheduled review covers it).
  enqueue(case_: QuarantineCase): void {
    const existing = this.pending.get(case_.ip);
    if (existing) {
      existing.case_ = case_;
      return;
    }
    const delayMs = Math.max(1, this.options.reviewAfterMinutes) * 60 * 1000;
    const timer = setTimeout(() => {
      this.pending.delete(case_.ip);
      this.review(case_).catch((e) => this.logger.error(`Quarantine review failed for ${case_.ip}`, e));
    }, delayMs);
    // Never keep the process alive just for a pending review.
    if (typeof timer.unref === 'function') timer.unref();
    this.pending.set(case_.ip, { case_, timer });
    this.logger.info(`Quarantine review scheduled: ${case_.ip} (${case_.nickname}) in ${this.options.reviewAfterMinutes}min`);
  }

  getStats() {
    return { ...this.stats, pending: this.pending.size };
  }

  private async review(case_: QuarantineCase): Promise<void> {
    const ipChecker = IpChecker.getInstance();
    const ml = MlDetector.getInstance();
    this.stats.reviewed++;

    const recheck = await ipChecker.recheckIp(case_.ip);
    const isBan = recheck.verdict === 'ban' || !!recheck.ban_confidence;

    if (isBan && recheck.ban_confidence === 'hard') {
      // Full pipeline now HARD-confirms (2+ independent sources / Tor /
      // blacklist) - the quarantine was right. Upgrade to the operator's
      // permanent ban duration. recheckIp already wrote the blacklist entry
      // and reputation/ML bookkeeping on its hard path.
      this.stats.escalated++;
      const config = ConfigManager.getInstance().getAll();
      const permanentMinutes = config.auto_ban?.ban_duration_minutes || 0;
      try {
        await this.rconService?.ban(case_.ip, permanentMinutes, config.auto_ban?.ban_reason || 'VPN/Proxy confirmed on review');
      } catch (e) {
        this.logger.error(`Quarantine escalation ban failed for ${case_.ip}`, e);
      }
      this.logger.warn(`QUARANTINE ESCALATED to permanent: ${case_.ip} (${case_.nickname}) - re-check hard-confirmed [${recheck.isp}]`);
      return;
    }

    if (isBan) {
      // Re-check still says ban, but still only at soft confidence - the
      // existing time-boxed quarantine already covers exactly this case, so
      // leave it be. Positive-but-weak: no ML label either way (still not a
      // resolved outcome).
      this.stats.upheld++;
      this.logger.info(`Quarantine upheld (still soft on re-check): ${case_.ip} (${case_.nickname})`);
      return;
    }

    // Re-check came back CLEAN.
    if (case_.result?.travel_flagged) {
      // The IP being clean doesn't refute a travel pattern (see file
      // header) - keep the time-boxed quarantine, just log it.
      this.stats.upheld++;
      this.logger.info(`Quarantine upheld (travel-flagged; IP-clean re-check doesn't refute movement evidence): ${case_.ip} (${case_.nickname})`);
      return;
    }

    // FP averted: lift the ban, purge the poisoned cache entry (recheckIp
    // already replaced it with the clean verdict, so the next connection
    // sails through on it), teach the model, tell the operator.
    this.stats.reverted++;
    try {
      await this.rconService?.unban(case_.ip);
    } catch (e) {
      this.logger.error(`Quarantine revert unban failed for ${case_.ip}`, e);
    }
    this.options.onUnban?.(case_.ip);
    // Negative training sample from the ORIGINAL quarantine's context where
    // available - "this pattern quarantined an innocent player".
    try {
      const features = ml.extractFeatures({
        isp: case_.result?.isp, org: case_.result?.organization,
        asn: case_.result?.asn, verifiedAsnHit: false,
      });
      ml.addTrainingSample(features, 0);
    } catch { /* training bookkeeping must never break the revert */ }
    this.logger.warn(`QUARANTINE REVERTED (FP averted): ${case_.ip} (${case_.nickname}) - full re-check came back clean [${recheck.isp || 'unknown ISP'}]`);
    try {
      await WebhookService.getInstance().sendInfo(
        'Quarantine Reverted (FP averted)',
        `**${case_.nickname}** (\`${case_.ip}\`) was quarantined but a full re-check came back clean. Ban lifted automatically.`,
        [
          { name: 'Original reason', value: `${case_.result?.isp || 'unknown'} (risk ${case_.result?.risk_score ?? '?'})`, inline: true },
          { name: 'Re-check ISP', value: recheck.isp || 'unknown', inline: true },
          { name: 'Totals', value: `${this.stats.reverted} reverted / ${this.stats.escalated} escalated / ${this.stats.upheld} upheld`, inline: false },
        ]
      );
    } catch { /* webhook failure must never break the revert */ }
  }
}
