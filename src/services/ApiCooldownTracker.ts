// src/services/ApiCooldownTracker.ts
//
// Tracks per-service rate-limit cooldowns for the Layer 1 IP-intelligence
// APIs in IpChecker.ts. Before this existed, a 429/quota-exceeded response
// was indistinguishable from any other failure - the service was simply
// retried on every single subsequent connection, burning whatever's left of
// an already-exhausted quota window. Once IpChecker's own rate-limit
// detection (see detectRateLimit in IpChecker.ts) recognizes a response as
// "out of requests", it calls markRateLimited() here and every call to that
// service short-circuits with zero network I/O until the cooldown elapses.
//
// In-memory only, same as this file's siblings (NetworkReputationStore,
// IpReputationStore, the ASN-verdict cache in IpChecker) - none of those
// persist across restarts either, so a restart simply re-learns the
// cooldown on the next 429 rather than being permanently correct across
// process lifetimes. That's an acceptable trade-off here: a fresh process
// re-trying once and getting re-rate-limited costs one wasted call, not a
// ban-affecting outcome.
import { Logger } from '../utils/Logger';

export class ApiCooldownTracker {
  private static instance: ApiCooldownTracker | null = null;
  private cooldowns: Map<string, number> = new Map(); // serviceId -> cooldownUntil (epoch ms)
  private logger: Logger;

  private constructor() {
    this.logger = Logger.getInstance();
  }

  static getInstance(): ApiCooldownTracker {
    if (!ApiCooldownTracker.instance) {
      ApiCooldownTracker.instance = new ApiCooldownTracker();
    }
    return ApiCooldownTracker.instance;
  }

  isOnCooldown(id: string): boolean {
    const until = this.cooldowns.get(id);
    if (!until) return false;
    if (Date.now() >= until) {
      this.cooldowns.delete(id);
      return false;
    }
    return true;
  }

  // Only logs on the transition into cooldown (not on every subsequent
  // skipped call) so a service that's rate-limited for hours doesn't spam
  // the log once per player connection.
  markRateLimited(id: string, cooldownSeconds: number): void {
    const wasAlreadyOnCooldown = this.isOnCooldown(id);
    const until = Date.now() + Math.max(1, cooldownSeconds) * 1000;
    this.cooldowns.set(id, until);
    if (!wasAlreadyOnCooldown) {
      this.logger.warn(`IpChecker: ${id} rate-limited, skipping for ${Math.round(cooldownSeconds / 60)}m`);
    }
  }

  getStats(): Record<string, { remainingSeconds: number }> {
    const now = Date.now();
    const stats: Record<string, { remainingSeconds: number }> = {};
    for (const [id, until] of this.cooldowns.entries()) {
      if (until > now) {
        stats[id] = { remainingSeconds: Math.round((until - now) / 1000) };
      }
    }
    return stats;
  }
}
