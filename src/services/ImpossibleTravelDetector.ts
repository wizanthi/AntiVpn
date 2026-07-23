// src/services/ImpossibleTravelDetector.ts
//
// WHY THIS EXISTS
// ----------------
// Every check in IpChecker.ts asks "is this IP, on its own, known to be a
// VPN/proxy/datacenter?". A rotating residential-proxy network defeats that
// by construction: each individual IP genuinely is someone's real home
// connection somewhere in the world, rented out for a few minutes at a
// time, so no reputation list will ever flag it. That's exactly the
// pattern in the sample log this was written for - one identity, five
// countries, roughly a minute apart each, every single IP coming back
// 0/100 clean.
//
// The signal that DOES exist in that pattern has nothing to do with IP
// reputation: no real player's connection can move a thousand kilometers a
// minute. This module tracks, per player identity, the last few places
// they connected from and the times, and flags the connection when the
// implied travel speed between two of them is physically impossible for a
// human being (even generously allowing for a commercial flight).
//
// FALSE-POSITIVE POSTURE
// -----------------------
// - The speed bar (see MAX_PLAUSIBLE_KMH) is set above commercial airline
//   cruise speed, not "wow that's a bit far". A legitimate player cannot
//   trip it by moving between cities, changing mobile towers, or switching
//   from home Wi-Fi to mobile data in the same country/region.
// - Nickname matching is exact-normalized by default (case/whitespace
//   only), which has effectively zero collision risk. The optional
//   "core" match (see normalizeCore) strips digits to also catch the
//   `basename` + random-digit-suffix evasion pattern (`carmine`,
//   `carmine341243`, `12carmine341243` all collapse to `carmine`) - this
//   is deliberately a *softer* signal and is only ever used to add
//   corroboration, never to ban on its own; see PlayerTracker wiring.
// - History is capped and time-windowed (see HISTORY_WINDOW_MS) so it
//   can't grow unbounded and can't match against a connection from days
//   ago where slow travel would be entirely plausible.

import { Logger } from '../utils/Logger';

interface TravelRecord {
  ip: string;
  countryCode: string; // ISO-2, uppercase
  at: number; // epoch ms
  // ASN announcing the IP at sighting time (null when the offline index
  // couldn't attribute it). Used to skip comparisons between two sightings
  // inside the SAME network: a mobile carrier's CGNAT pool relocating its
  // public exit (or a GeoIP source disagreeing about where that pool "is")
  // produces an apparent country hop with zero actual travel - a real
  // rotating-proxy pool, by contrast, hops across many DIFFERENT networks.
  asn: number | null;
}

export interface TravelCheckResult {
  flagged: boolean;
  reason?: string;
  impliedKmh?: number;
  priorCountry?: string;
  priorIp?: string;
  minutesSince?: number;
}

// Approximate country centroids (ISO-2 -> [lat, lon]). Good enough for a
// physics sanity check at these distances/speeds - being off by a few
// hundred km inside a country never flips a multi-thousand-km/h verdict.
const COUNTRY_CENTROIDS: Record<string, [number, number]> = {
  US: [39.8, -98.6], CA: [56.1, -106.3], MX: [23.6, -102.6],
  GB: [54.0, -2.0], IE: [53.4, -8.2], FR: [46.6, 2.2], DE: [51.2, 10.4],
  ES: [40.5, -3.7], PT: [39.4, -8.2], IT: [41.9, 12.6], NL: [52.1, 5.3],
  BE: [50.5, 4.5], CH: [46.8, 8.2], AT: [47.5, 14.6], SE: [60.1, 18.6],
  NO: [60.5, 8.5], FI: [61.9, 25.7], DK: [56.3, 9.5], PL: [51.9, 19.1],
  CZ: [49.8, 15.5], SK: [48.7, 19.7], HU: [47.2, 19.5], RO: [45.9, 24.9],
  BG: [42.7, 25.5], GR: [39.1, 21.8], UA: [48.4, 31.2], RU: [61.5, 105.3],
  TR: [38.9, 35.2], IL: [31.0, 34.9], SA: [23.9, 45.1], AE: [23.4, 53.8],
  EG: [26.8, 30.8], ZA: [-30.6, 22.9], NG: [9.1, 8.7], KE: [-0.02, 37.9],
  IN: [20.6, 79.0], PK: [30.4, 69.3], BD: [23.7, 90.4], LK: [7.9, 80.8],
  CN: [35.9, 104.2], JP: [36.2, 138.3], KR: [35.9, 127.8], KP: [40.3, 127.5],
  TW: [23.7, 121.0], HK: [22.3, 114.2], MO: [22.2, 113.5],
  TH: [15.9, 100.99], VN: [14.1, 108.3], PH: [12.9, 121.8], MY: [4.2, 101.9],
  SG: [1.35, 103.8], ID: [-0.8, 113.9], MM: [21.9, 95.96], KH: [12.6, 105.0],
  LA: [19.9, 102.5], AU: [-25.3, 133.8], NZ: [-41.0, 174.9],
  BR: [-14.2, -51.9], AR: [-38.4, -63.6], CL: [-35.7, -71.5], CO: [4.6, -74.3],
  PE: [-9.2, -75.0], VE: [6.4, -66.6], EC: [-1.8, -78.2], BO: [-16.3, -63.6],
  UY: [-32.5, -55.8], PY: [-23.4, -58.4],
  KZ: [48.0, 66.9], UZ: [41.4, 64.6], MN: [46.9, 103.8],
  IQ: [33.2, 43.7], IR: [32.4, 53.7], JO: [30.6, 36.2], LB: [33.9, 35.9],
  QA: [25.4, 51.2], KW: [29.3, 47.5], OM: [21.5, 55.9], BH: [26.0, 50.6],
  MA: [31.8, -7.1], DZ: [28.0, 1.7], TN: [33.9, 9.5], LY: [26.3, 17.2],
  GH: [7.9, -1.0], ET: [9.1, 40.5], TZ: [-6.4, 34.9], UG: [1.4, 32.3],
  IS: [64.9, -19.0], LU: [49.8, 6.1], MT: [35.9, 14.4], CY: [35.1, 33.4],
  EE: [58.6, 25.0], LV: [56.9, 24.6], LT: [55.2, 23.9], HR: [45.1, 15.2],
  SI: [46.1, 14.8], RS: [44.0, 21.0], BA: [43.9, 17.7], AL: [41.2, 20.2],
  MD: [47.4, 28.4], BY: [53.7, 27.9], GE: [42.3, 43.4], AM: [40.1, 45.0],
  AZ: [40.1, 47.6], NP: [28.4, 84.1], AF: [33.9, 67.7],
};

const MAX_PLAUSIBLE_KMH = 900; // above commercial airline cruise speed
// Below this time gap a country change is flagged even if the centroid
// table doesn't have both countries - crossing any land border, let alone
// an ocean, inside a couple of minutes isn't possible regardless of exact
// distance.
const MIN_MINUTES_FOR_ANY_COUNTRY_CHANGE = 3;
// Wide enough to also catch SLOW rotation - a proxy pool that waits 20-30
// minutes between swaps, deliberately staying under the speed threshold,
// still can't explain one identity legitimately being in 4+ different
// countries within a few hours. That's the diversity check below; it's a
// second, independent tripwire from the speed one, not a replacement.
const HISTORY_WINDOW_MS = 4 * 60 * 60 * 1000; // 4 hours
const MAX_HISTORY_PER_KEY = 20;
const DIVERSITY_COUNTRY_THRESHOLD = 4; // distinct countries within the window
const DIVERSITY_MIN_MINUTES_SPAN = 5; // ignore near-simultaneous dupes/noise
// How often to sweep stale map keys entirely (see sweepStale below) - not
// tied to HISTORY_WINDOW_MS itself, just needs to be frequent enough that
// the maps can't grow unbounded between sweeps.
const SWEEP_INTERVAL_MS = 15 * 60 * 1000; // 15 minutes

function haversineKm(a: [number, number], b: [number, number]): number {
  const [lat1, lon1] = a, [lat2, lon2] = b;
  const R = 6371;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const s = Math.sin(dLat / 2) ** 2 +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(s));
}

export class ImpossibleTravelDetector {
  private static instance: ImpossibleTravelDetector | null = null;
  private logger: Logger;
  // exact-normalized nickname -> recent sightings
  private exactHistory: Map<string, TravelRecord[]> = new Map();
  // digit-stripped "core" nickname -> recent sightings (softer signal)
  private coreHistory: Map<string, TravelRecord[]> = new Map();
  private lastSweptAt: number = 0;

  private constructor() { this.logger = Logger.getInstance(); }

  // DDNet nicknames are arbitrary and player-chosen, and prune() above only
  // trims the *array* under each map key down to its recent window - the
  // key itself lives forever once created. Without this, anyone can grow
  // both maps without bound simply by connecting (even briefly) with a new
  // nickname each time - an easy, low-effort memory-exhaustion DoS against
  // the very bot meant to stop abuse. Sweeping is rate-limited to once per
  // SWEEP_INTERVAL_MS (not run on every check() call) since it's an O(n)
  // scan over every key currently held.
  private sweepStale(now: number): void {
    if (now - this.lastSweptAt < SWEEP_INTERVAL_MS) return;
    this.lastSweptAt = now;
    for (const map of [this.exactHistory, this.coreHistory]) {
      for (const [key, list] of map) {
        const newest = list.length > 0 ? list[list.length - 1].at : 0;
        if (now - newest > HISTORY_WINDOW_MS) map.delete(key);
      }
    }
  }

  static getInstance(): ImpossibleTravelDetector {
    return ImpossibleTravelDetector.instance || (ImpossibleTravelDetector.instance = new ImpossibleTravelDetector());
  }

  private normalizeExact(nickname: string): string {
    return (nickname || '').trim().toLowerCase();
  }

  // Strips everything but letters, collapsing `carmine`, `carmine341243`,
  // `12carmine341243` to the same key. Deliberately only used as a softer,
  // corroborating signal (see record()'s `soft` field) - never sufficient
  // to ban by itself, since short common nicknames can collide.
  private normalizeCore(nickname: string): string {
    return (nickname || '').toLowerCase().replace(/[^a-z]/g, '');
  }

  private prune(list: TravelRecord[], now: number): TravelRecord[] {
    const cut = list.filter(r => now - r.at <= HISTORY_WINDOW_MS);
    return cut.slice(-MAX_HISTORY_PER_KEY);
  }

  private evaluateDiversity(history: TravelRecord[], countryCode: string, now: number): TravelCheckResult {
    const span = history.filter(r => now - r.at <= HISTORY_WINDOW_MS);
    const countries = new Set(span.map(r => r.countryCode));
    countries.add(countryCode);
    if (countries.size < DIVERSITY_COUNTRY_THRESHOLD) return { flagged: false };
    // FP-hardening: if every sighting in the window came from ONE known
    // network operator, the "diversity" is that operator's GeoIP scatter
    // (an international carrier's CGNAT pool attributed to several
    // countries), not a proxy pool. A real rotating-residential pool rides
    // many different consumer ISPs, so requiring a second distinct ASN
    // costs detection nothing.
    const asns = new Set(span.map(r => r.asn).filter((a): a is number => a !== null));
    if (asns.size === 1) return { flagged: false };
    const oldest = span.reduce((min, r) => Math.min(min, r.at), now);
    const spanMinutes = (now - oldest) / 60000;
    if (spanMinutes < DIVERSITY_MIN_MINUTES_SPAN) return { flagged: false }; // avoid flagging on noisy near-duplicate reconnects
    return {
      flagged: true,
      reason: `${countries.size} distinct countries (${Array.from(countries).join(', ')}) within ${Math.round(spanMinutes)}min`,
      minutesSince: spanMinutes,
    };
  }

  private evaluate(history: TravelRecord[], countryCode: string, ip: string, asn: number | null, now: number): TravelCheckResult {
    for (let i = history.length - 1; i >= 0; i--) {
      const prev = history[i];
      if (prev.countryCode === countryCode || prev.ip === ip) continue;
      // FP-hardening: same ASN on both sides = the same network operator
      // (mobile CGNAT/carrier pool) whose exit or GeoIP attribution moved -
      // not a human teleporting. A genuine rotating residential-proxy pool
      // spans many different consumer ISPs (different ASNs), so skipping
      // same-ASN pairs costs it nothing.
      if (asn !== null && prev.asn !== null && prev.asn === asn) continue;
      const minutesSince = (now - prev.at) / 60000;
      if (minutesSince <= 0) continue;

      const a = COUNTRY_CENTROIDS[prev.countryCode];
      const b = COUNTRY_CENTROIDS[countryCode];
      if (a && b) {
        const km = haversineKm(a, b);
        const impliedKmh = km / (minutesSince / 60);
        if (impliedKmh > MAX_PLAUSIBLE_KMH) {
          return {
            flagged: true,
            reason: `Impossible travel: ${prev.countryCode} -> ${countryCode} in ${minutesSince.toFixed(1)}min (~${Math.round(impliedKmh).toLocaleString()} km/h implied)`,
            impliedKmh, priorCountry: prev.countryCode, priorIp: prev.ip, minutesSince,
          };
        }
      } else if (minutesSince < MIN_MINUTES_FOR_ANY_COUNTRY_CHANGE) {
        // Unknown centroid for one side - fall back to a conservative
        // "any country change this fast is impossible" rule.
        return {
          flagged: true,
          reason: `Impossible travel: ${prev.countryCode} -> ${countryCode} in ${minutesSince.toFixed(1)}min`,
          priorCountry: prev.countryCode, priorIp: prev.ip, minutesSince,
        };
      }
    }
    return { flagged: false };
  }

  /**
   * Records a sighting and checks it against recent history for the same
   * identity. Call this for EVERY connection regardless of what the IP
   * reputation check said - that's the point, this signal is independent
   * of it. Returns both the strict (exact-nickname) verdict and a soft
   * (digit-stripped) verdict; see PlayerTracker for how each is used.
   */
  check(nickname: string, countryCode: string | undefined, ip: string, asn: number | null = null): { strict: TravelCheckResult; soft: TravelCheckResult } {
    const now = Date.now();
    this.sweepStale(now);
    const cc = (countryCode || '').toUpperCase();
    if (!cc || cc.length !== 2) return { strict: { flagged: false }, soft: { flagged: false } };

    const exactKey = this.normalizeExact(nickname);
    const coreKey = this.normalizeCore(nickname);

    const exactList = this.prune(this.exactHistory.get(exactKey) || [], now);
    const coreList = this.prune(this.coreHistory.get(coreKey) || [], now);

    const strict = this.evaluate(exactList, cc, ip, asn, now);
    const strictDiversity = this.evaluateDiversity(exactList, cc, now);
    // Only bother with the softer core check if it's a *different* key
    // (short/common nicknames where core === exact add no extra info).
    const softDifferent = coreKey && coreKey !== exactKey;
    const soft = softDifferent ? this.evaluate(coreList, cc, ip, asn, now) : { flagged: false };
    const softDiversity = softDifferent ? this.evaluateDiversity(coreList, cc, now) : { flagged: false };

    exactList.push({ ip, countryCode: cc, at: now, asn });
    this.exactHistory.set(exactKey, exactList);
    if (coreKey) {
      coreList.push({ ip, countryCode: cc, at: now, asn });
      this.coreHistory.set(coreKey, coreList);
    }

    const strictOut = strict.flagged ? strict : strictDiversity;
    const softOut = soft.flagged ? soft : softDiversity;

    if (strictOut.flagged) this.logger.warn(`TRAVEL: "${nickname}" ${strictOut.reason}`);
    else if (softOut.flagged) this.logger.warn(`TRAVEL (soft/core-match): "${nickname}" ~"${coreKey}" ${softOut.reason}`);

    return { strict: strictOut, soft: softOut };
  }

  clear(): void { this.exactHistory.clear(); this.coreHistory.clear(); }
}
