// src/core/PlayerTracker.ts
import { TrackedPlayer, IpCheckResult, StatusPlayer } from '../types';
import { Logger } from '../utils/Logger';
import { ListManager } from '../services/ListManager';
import { IpChecker } from '../services/IpChecker';
import { WebhookService } from '../services/WebhookService';
import { CacheService } from '../utils/Cache';
import { ConfigManager } from '../config/ConfigManager';
import { CustomBanManager } from '../services/CustomBanManager';
import { ImpossibleTravelDetector } from '../services/ImpossibleTravelDetector';
import { QuarantineReviewer } from '../services/QuarantineReviewer';

export class PlayerTracker {
  private static instance: PlayerTracker;
  private players: Map<number, TrackedPlayer>;
  private logger: Logger;
  private listManager: ListManager;
  private ipChecker: IpChecker;
  private webhookService: WebhookService;
  private cache: CacheService;
  private rconService: any;
  private customBanManager: CustomBanManager;
  private travelDetector: ImpossibleTravelDetector;
  private quarantineReviewer: QuarantineReviewer | null = null;
  private bannedIps: Set<string> = new Set();
  private leaveCheckedIds: Set<number> = new Set();
  private config: any;
  private botNickname: string;
  private maxParallelChecks: number;
  private travelEnabled: boolean;
  private travelSoftMatchEnabled: boolean;
  // Bounded-concurrency queue shared by real-time join checks AND
  // leave checks (see enqueueJoinCheck / checkPlayerOnLeave). A bot swarm
  // fires many joins - and later many leaves - in the same instant; without
  // this, each one launched an unbounded IP check immediately and the
  // resulting API flood made checks fail open as "trusted".
  private checkQueue: Array<() => Promise<void>> = [];
  private activeChecks: number = 0;
  // Real nicknames that resolved while the player's IP check was still in
  // flight (i.e. before trackPlayer created the entry) - consumed by
  // trackPlayer so the tracked record and webhooks get the real name even
  // though the check started from a placeholder join-line callback.
  private pendingNames: Map<number, { nickname: string; clan: string }> = new Map();

  private constructor() {
    this.players = new Map();
    this.logger = Logger.getInstance();
    this.listManager = ListManager.getInstance();
    this.ipChecker = IpChecker.getInstance();
    this.webhookService = WebhookService.getInstance();
    this.cache = CacheService.getInstance();
    this.customBanManager = CustomBanManager.getInstance();
    this.travelDetector = ImpossibleTravelDetector.getInstance();
    this.config = ConfigManager.getInstance().getAll();
    this.botNickname = this.config.bot?.nickname || 'WizanthiAntiVpn';
    this.maxParallelChecks = this.config.ipcheck?.max_parallel_checks || 50;
    this.travelEnabled = this.config.impossible_travel?.enabled ?? true;
    this.travelSoftMatchEnabled = this.config.impossible_travel?.use_soft_match ?? true;
    this.logger.info(`Mode: ${this.getMode().toUpperCase()} (AutoBan: ${this.isAutoBanEnabled() ? 'ON' : 'OFF'})`);
  }

  static getInstance(): PlayerTracker { 
    return PlayerTracker.instance || (PlayerTracker.instance = new PlayerTracker()); 
  }

  setRconService(rconService: any): void {
    this.rconService = rconService;
    this.customBanManager.setRconService(rconService);
    // The re-verification worker needs RCON (to unban on refute / re-ban
    // permanent on escalate), so it's wired up alongside it.
    const q = this.config.auto_ban?.quarantine;
    if (q?.auto_review !== false) { // default on
      this.quarantineReviewer = QuarantineReviewer.getInstance();
      this.quarantineReviewer.init(rconService, {
        reviewAfterMinutes: q?.review_after_minutes ?? 6,
        onUnban: (ip: string) => { this.bannedIps.delete(ip); },
      });
    }
  }

  private getMode(): 'warn' | 'autoban' { 
    return this.config.auto_ban?.mode || 'warn'; 
  }

  private isAutoBanEnabled(): boolean { 
    return this.config.auto_ban?.enabled ?? false; 
  }

  // Master switch, read live (not cached from this.config) so a runtime
  // `$sudo antivpn enable 1/0` takes effect on the very next check/ban
  // decision. While OFF, every IP-check and tracking path below still runs
  // (so joins get checked and flagged in real time) but every actual ban/
  // custom-ban execution is gated on this - "disabled" must mean checks
  // keep happening, nothing gets acted on. See banAllPendingSuspicious()
  // for what runs the instant the switch flips back ON.
  private isAntiVpnEnabled(): boolean {
    return ConfigManager.getInstance().isAntiVpnEnabled();
  }

  // CHECK CUSTOM BANS BEFORE EVERYTHING
  private async checkCustomBan(sp: StatusPlayer): Promise<boolean> {
    if (!this.customBanManager.isCustomBanned(sp.ip)) {
      return false;
    }

    const banInfo = this.customBanManager.getBanInfo(sp.ip);
    if (!banInfo || !banInfo.enabled) {
      return false;
    }

    this.logger.warn(`CUSTOM BAN: ${sp.nickname} (${sp.ip}) - ${banInfo.reason}`);

    // Track player
    const tracked = this.trackPlayer(sp, {
      is_whitelisted: false, 
      is_blacklisted: true, 
      is_vpn: false,
      is_proxy: false, 
      is_suspicious: true, 
      is_trusted: false
    });

    // Execute ban immediately - but only while the master switch is ON.
    // Disabled means "keep detecting, never act"; the player above is still
    // tracked as banInfo-flagged so banAllPendingSuspicious() can act on it
    // the instant AntiVPN gets re-enabled.
    // A custom ban is an explicit operator decision, so it does not depend
    // on automatic-detection mode. The global AntiVPN master switch still
    // pauses enforcement while leaving the IP tracked for later action.
    if (this.isAntiVpnEnabled()) {
      await this.customBanManager.executeBan(sp.ip);
      this.bannedIps.add(sp.ip);
    }

    // Send webhook
    try {
      await this.webhookService.sendVpnDetectionAlert(tracked, {
        ip: sp.ip, 
        is_vpn: false, 
        is_proxy: false, 
        is_tor: false,
        is_hosting: false, 
        is_datacenter: false, 
        risk_score: 100,
        threat_level: 'critical', 
        checked_at: new Date().toISOString(), 
        cached: false,
        country: 'Custom Ban',
        city: '',
        isp: banInfo.reason,
        organization: `Duration: ${banInfo.duration_minutes === 0 ? 'Permanent' : banInfo.duration_minutes + 'min'}`
      });
    } catch (e) {
      this.logger.error('Failed to send custom ban webhook', e);
    }

    return true;
  }

  async processStatus(statusPlayers: StatusPlayer[]): Promise<void> {
    const currentIds = new Set(statusPlayers.map(p => p.id));
    for (const [id] of this.players) {
      if (!currentIds.has(id)) {
        await this.checkPlayerOnLeave(id);
        this.players.delete(id);
        // Client IDs are reused by the server - a parked name left behind
        // here would mislabel the next player who gets this ID.
        this.pendingNames.delete(id);
      }
    }

    const playersToCheck: StatusPlayer[] = [];
    for (const sp of statusPlayers) {
      if (sp.nickname === this.botNickname) continue;

      // CHECK CUSTOM BANS FIRST
      const isCustomBanned = await this.checkCustomBan(sp);
      if (isCustomBanned) {
        continue; // Skip further checks - already banned
      }

      if (this.listManager.isWhitelisted(sp.ip) || this.listManager.isPrivateIP(sp.ip)) {
        this.trackPlayer(sp, { 
          is_whitelisted: true, is_blacklisted: false, is_vpn: false, 
          is_proxy: false, is_suspicious: false, is_trusted: true 
        });
        continue;
      }

      if (this.listManager.isBlacklisted(sp.ip)) {
        this.trackPlayer(sp, { 
          is_whitelisted: false, is_blacklisted: true, is_vpn: true, 
          is_proxy: false, is_suspicious: true, is_trusted: false 
        });
        if (this.getMode() === 'autoban' && this.isAutoBanEnabled() && this.isAntiVpnEnabled() && !this.bannedIps.has(sp.ip)) {
          await this.autoBan(sp);
        }
        continue;
      }

      const cachedRaw = this.cache.get(sp.ip);
      if (cachedRaw) {
        const susFromIp = this.isSuspiciousResult(sp.ip, cachedRaw);
        const { sus, result: cached } = this.applyTravelCheck(sp, cachedRaw, susFromIp);
        this.trackPlayer(sp, { 
          is_whitelisted: !sus, is_blacklisted: sus, is_vpn: cached.is_vpn, 
          is_proxy: cached.is_proxy, is_suspicious: sus, is_trusted: !sus 
        }, cached);
        if (sus && this.getMode() === 'autoban' && this.isAutoBanEnabled() && this.isAntiVpnEnabled() && !this.bannedIps.has(sp.ip)) {
          await this.autoBan(sp, cached);
        }
        continue;
      }

      playersToCheck.push(sp);
    }

    if (playersToCheck.length > 0) {
      for (let i = 0; i < playersToCheck.length; i += this.maxParallelChecks) {
        const batch = playersToCheck.slice(i, i + this.maxParallelChecks);
        await Promise.allSettled(batch.map(p => this.checkIpForPlayer(p)));
        if (i + this.maxParallelChecks < playersToCheck.length) await this.delay(100);
      }
    }
  }

  // Single source of truth for "did the IP check flag this player?".
  //
  // FP-hardening (v8.4): decided by IpChecker's own explicit verdict, not
  // re-inferred here from side-channel fields. The old inference treated
  // ANY r.dataset_match or threat_level high/critical as suspicious - but
  // in corroborate mode IpChecker attaches dataset_match to EVERY result
  // (including CLEAN ones, purely as enrichment for webhooks/dashboards),
  // and the clean path sets threat_level from the risk level "for
  // visibility without treating it as a ban". Both together meant every
  // player whose IP appeared in any dataset file - or who scored
  // high-composite but was explicitly cleared by the min-independent-
  // signals rule - was banned here anyway, with NO ban_confidence (so it
  // defaulted to a PERMANENT ban). That single inference bypassed the
  // entire corroborate-mode FP guard and was the largest observed source
  // of dataset false positives.
  //
  // A result is suspicious iff:
  //  - IpChecker said verdict='ban' (every real ban path sets this), or
  //  - legacy cached result without `verdict` (persisted by an older
  //    version): fall back to the category booleans + ban_confidence -
  //    fields only ever set on genuine ban results - plus the blacklist.
  //  - the IP is persistently blacklisted (operator data, always acted on).
  // Detection is unchanged: every path that previously produced an actual
  // ban result still lands here as suspicious; only the two clean-result
  // leaks are closed.
  private isSuspiciousResult(ip: string, r: IpCheckResult): boolean {
    if (this.listManager.isBlacklisted(ip)) return true;
    if (r.verdict) return r.verdict === 'ban';
    return !!(
      r.is_vpn || r.is_proxy || r.is_tor || r.is_hosting || r.is_datacenter ||
      r.ban_confidence
    );
  }

  // Runs the impossible-travel behavioral check and folds it into an
  // existing IP-reputation verdict. This is deliberately independent of
  // whatever the IP-based checks concluded - a "clean" IP with a physically
  // impossible location jump for the same identity is still a ban, because
  // that's precisely the case a rotating residential-proxy pool produces
  // (every individual IP looks clean; the pattern across IPs does not).
  private applyTravelCheck(sp: StatusPlayer, result: IpCheckResult, alreadySus: boolean): { sus: boolean; result: IpCheckResult } {
    if (!this.travelEnabled || !result.country || !/^[A-Za-z]{2}$/.test(result.country)) {
      return { sus: alreadySus, result };
    }
    // Never feed placeholder identities ('Unknown', Player_N) to the travel
    // detector: during a swarm many joiners get checked before their real
    // name resolves, and they'd all share one placeholder identity - two
    // 'Unknown's from different countries within minutes would fabricate an
    // "impossible travel" hit and quarantine whoever joins unnamed next.
    if (this.isPlaceholderName(sp.nickname) || this.isGeneratedPlayerName(sp.nickname)) {
      return { sus: alreadySus, result };
    }
    const { strict, soft } = this.travelDetector.check(sp.nickname, result.country, sp.ip, result.asn ?? null);

    if (strict.flagged) {
      // FP-hardening: impossible-travel is a behavioral inference and is
      // GeoIP-error-prone (a wrong country from one lookup fabricates an
      // impossible jump). It still acts immediately, but as a SOFT
      // quarantine + review rather than a permanent blacklist entry.
      // v8.4: when the offline ASN index attributes the IP to a DIFFERENT
      // country than the API verdict, the two geo sources disagree - the
      // "jump" is then more likely a GeoIP attribution error than actual
      // movement, so the strict hit downgrades to the soft (corroborate-
      // only) tier instead of firing on a country nobody can corroborate.
      const geoDisputed = !!(result.asn_country && result.country &&
        result.asn_country.toUpperCase() !== result.country.toUpperCase());
      if (!geoDisputed) {
        const merged: IpCheckResult = { ...result, verdict: 'ban', risk_score: 100, threat_level: 'critical', ban_confidence: 'soft', travel_flagged: true };
        this.logger.warn(`IMPOSSIBLE TRAVEL (quarantine): ${sp.nickname} (${sp.ip}) - ${strict.reason}`);
        return { sus: true, result: merged };
      }
      this.logger.warn(`IMPOSSIBLE TRAVEL (geo sources disagree: API=${result.country} ASN-index=${result.asn_country}) - treating as soft corroboration only: ${sp.nickname} (${sp.ip})`);
      if (!alreadySus && this.travelSoftMatchEnabled) {
        const merged: IpCheckResult = { ...result, verdict: 'ban', risk_score: Math.max(result.risk_score || 0, 60), threat_level: 'medium', ban_confidence: 'soft', travel_flagged: true };
        return { sus: true, result: merged };
      }
      return { sus: alreadySus, result };
    }
    // Soft (digit-stripped nickname) match: same corroboration-only
    // posture as everything else in this codebase - only acted on if the
    // IP wasn't already going to be flagged some other way, and only if
    // the operator hasn't disabled it (short/common nicknames can collide).
    if (this.travelSoftMatchEnabled && soft.flagged && !alreadySus) {
      const merged: IpCheckResult = { ...result, verdict: 'ban', risk_score: Math.max(result.risk_score || 0, 60), threat_level: 'medium', ban_confidence: 'soft', travel_flagged: true };
      this.logger.warn(`IMPOSSIBLE TRAVEL (soft nickname match, quarantine): ${sp.nickname} (${sp.ip}) - ${soft.reason}`);
      return { sus: true, result: merged };
    }
    return { sus: alreadySus, result };
  }

  // Bounded-concurrency entry point for real-time joins, used by the join
  // listener instead of calling checkIpForPlayer directly.
  //
  // A bot swarm can fire 20-30 joins within the same second. Calling
  // checkIpForPlayer() directly for each launched that many IP checks at
  // once, and every IP check fans out to ~15 external intelligence APIs - so
  // 25 joins meant ~375 concurrent outbound requests. That overruns the
  // per-service rate limits, the checks start failing, and a failed check
  // falls through to the fail-open "trusted" branch below (a transient error
  // must not ban a legitimate player) - i.e. under a burst the whole swarm
  // slips past as "trusted". Funnelling joins through the SAME
  // max_parallel_checks cap the periodic status scan already uses keeps every
  // player in the burst actually getting a real check instead of a fail-open
  // pass. Order within the cap is FIFO, so earlier joiners are checked first.
  enqueueJoinCheck(sp: StatusPlayer): void {
    this.enqueueCheck(() => this.checkIpForPlayer(sp), `join check for ${sp.nickname} (${sp.ip})`);
  }

  // Called when the batched name resolver learns a joiner's real nickname
  // after their IP check already started from a placeholder join-line
  // callback. Updates the live record if it exists, otherwise parks the
  // name for trackPlayer to consume when the in-flight check completes.
  updatePlayerName(id: number, nickname: string, clan: string): void {
    if (!nickname || this.isPlaceholderName(nickname)) return;
    const player = this.players.get(id);
    if (player) {
      player.nickname = nickname;
      if (clan) player.clan = clan;
    } else {
      this.pendingNames.set(id, { nickname, clan: clan || '' });
    }
  }

  private enqueueCheck(task: () => Promise<void>, label: string): void {
    this.checkQueue.push(async () => {
      // The underlying checks already swallow their own errors, but guard
      // here too so one rejection can't wedge the queue - the slot must
      // always be released to pull the next queued check.
      try {
        await task();
      } catch (e) {
        this.logger.error(`Queued ${label} failed`, e);
      }
    });
    this.pumpCheckQueue();
  }

  private pumpCheckQueue(): void {
    while (this.activeChecks < this.maxParallelChecks && this.checkQueue.length > 0) {
      const run = this.checkQueue.shift()!;
      this.activeChecks++;
      run().finally(() => {
        this.activeChecks--;
        this.pumpCheckQueue();
      });
    }
  }

  async checkIpForPlayer(sp: StatusPlayer): Promise<void> {
    // Check custom bans first
    if (this.customBanManager.isCustomBanned(sp.ip)) {
      const banInfo = this.customBanManager.getBanInfo(sp.ip);
      if (banInfo?.enabled) {
        this.logger.warn(`Custom ban check: ${sp.nickname} (${sp.ip}) - ${banInfo.reason}`);
        // Track it regardless of the master switch so banAllPendingSuspicious()
        // has a record to act on the instant AntiVPN gets re-enabled.
        this.trackPlayer(sp, {
          is_whitelisted: false, is_blacklisted: true, is_vpn: false,
          is_proxy: false, is_suspicious: true, is_trusted: false
        });
        // Explicit custom bans are enforced on every new join independently
        // of auto-ban mode; only the global AntiVPN master switch pauses it.
        if (this.isAntiVpnEnabled()) {
          await this.customBanManager.executeBan(sp.ip);
          this.bannedIps.add(sp.ip);
        }
        return;
      }
    }

    // NOTE: deliberately NO nickname-based skip here. An earlier version
    // returned early for generated-looking names (Player_N), which meant a
    // bot could exempt itself from ALL checks just by choosing that
    // nickname. The check and ban are keyed on the IP; a name must never
    // opt a connection out of them.

    // NOTE: no per-IP "already checking" short-circuit here. Two players
    // behind one NAT/household address is common, and an early return keyed
    // on the IP would drop the second player entirely - never tracked,
    // absent from stats, no leave-check, no webhook. The duplicate *network*
    // work is already deduped one level down: IpChecker.checkIp() reuses a
    // single in-flight promise per IP, so both players share one lookup
    // while each still gets tracked and handled individually.
    try {
      const rawResult = await this.ipChecker.checkIp(sp.ip);
      const susFromIp = this.isSuspiciousResult(sp.ip, rawResult);
      const { sus, result } = this.applyTravelCheck(sp, rawResult, susFromIp);
      const flags = { 
        is_whitelisted: !sus && (result.risk_score ?? 0) < 30, 
        is_blacklisted: sus, 
        is_vpn: result.is_vpn, 
        is_proxy: result.is_proxy, 
        is_suspicious: sus, 
        is_trusted: !sus 
      };
      const tracked = this.trackPlayer(sp, flags, result);
      // Log/alert with the RESOLVED name from tracking, not sp.nickname: the
      // check starts from the join line with the 'Unknown' placeholder, and
      // the real nickname usually lands (via chat-join / batched resolver ->
      // pendingNames) before the check finishes - trackPlayer just merged it.
      const displayName = tracked.nickname;

      if (sus) {
        if (this.getMode() === 'autoban' && this.isAutoBanEnabled() && this.isAntiVpnEnabled() && !this.bannedIps.has(sp.ip)) {
          await this.autoBan({ ...sp, nickname: displayName, clan: tracked.clan }, result);
        }

        this.logger.warn(`SUSPICIOUS: ${displayName} (${sp.ip}) - Score: ${result.risk_score}`);

        if (this.getMode() === 'warn') {
          await this.webhookService.sendWarning('Warn Mode', `**${displayName}** VPN/Proxy detected. Ban not executed.`, [
            { name: 'IP', value: `\`${sp.ip}\``, inline: true }, 
            { name: 'ID', value: String(sp.id), inline: true }
          ]);
        }

        try { await this.webhookService.sendVpnDetectionAlert(tracked, result); } catch (e) {}
      } else {
        this.logger.info(`Clean: ${displayName} (${sp.ip})`);
        try { await this.webhookService.sendCleanPlayerInfo(tracked, result); } catch (e) {}
      }
    } catch (error) {
      this.logger.error(`IP check failed for ${sp.nickname} (${sp.ip})`, error);
      this.trackPlayer(sp, {
        is_whitelisted: false, is_blacklisted: false, is_vpn: false,
        is_proxy: false, is_suspicious: false, is_trusted: true
      });
    }
  }

  // ... rest of the class remains the same ...
  async checkPlayerOnLeave(clientId: number): Promise<void> {
    if (this.leaveCheckedIds.has(clientId)) return;
    const player = this.players.get(clientId);
    if (!player) return;
    if (this.bannedIps.has(player.ip)) return;
    if (player.flags.is_trusted && player.ip_check) return;
    if (this.listManager.isWhitelisted(player.ip)) return;
    
    this.leaveCheckedIds.add(clientId);
    // Route through the same bounded queue as join checks: a swarm
    // disconnecting en masse used to fire one unbounded external lookup per
    // leaver, stacked on top of whatever join checks were still in flight.
    this.enqueueCheck(() => this.doLeaveCheck(player), `leave check for ${player.nickname} (${player.ip})`);
  }

  private async doLeaveCheck(player: TrackedPlayer): Promise<void> {
    this.logger.info(`Checking IP after leave: ${player.nickname} (${player.ip})`);

    try {
      const result = await this.ipChecker.checkIp(player.ip);
      const sus = this.isSuspiciousResult(player.ip, result);
      
      player.flags = { 
        is_whitelisted: !sus, is_blacklisted: sus, is_vpn: result.is_vpn, 
        is_proxy: result.is_proxy, is_suspicious: sus, is_trusted: !sus 
      };
      player.ip_check = result;
      
      if (sus) {
        if (this.getMode() === 'autoban' && this.isAutoBanEnabled() && this.isAntiVpnEnabled() && !this.bannedIps.has(player.ip)) {
          await this.autoBan({ id: player.id, nickname: player.nickname, clan: player.clan, ip: player.ip, score: 0, latency: 0 }, result);
        }
        this.logger.warn(`Player left but VPN detected: ${player.nickname} (${player.ip})`);
        try { await this.webhookService.sendVpnDetectionAlert(player, result); } catch (e) {}
      } else {
        this.logger.info(`Player left, IP clean: ${player.nickname}`);
      }
    } catch (error) {
      this.logger.error(`Failed to check IP for left player`, error);
    }
  }

  private async autoBan(player: StatusPlayer, ipCheck?: IpCheckResult): Promise<void> {
    if (!this.rconService) return;
    // Belt-and-suspenders: every call site above already gates on
    // isAntiVpnEnabled(), but enforcing it here too means "disabled" can
    // never accidentally ban no matter which path reaches autoBan().
    if (!this.isAntiVpnEnabled()) return;

    // FP-hardening: the ban's confidence tier (set by IpChecker on the
    // IpCheckResult) decides permanent-vs-quarantine.
    //   'hard' -> permanent ban (2+ independent signals, Tor, or the operator's
    //             own blacklist/custom-ban).
    //   'soft' -> time-boxed quarantine + a human-review webhook, so a
    //             medium-confidence detection can never become a silent
    //             permanent false-positive ban.
    // v8.4: unknown provenance must never mean permanent. No ipCheck at all
    // (persistent-blacklist path - an operator-curated hard decision) stays
    // 'hard'; an ipCheck WITHOUT ban_confidence (legacy cached entry, or a
    // result that reached here through an inference rather than an explicit
    // ban path) now defaults to 'soft' - it gets the same immediate
    // time-boxed ban, review webhook, and re-verification, it just can't
    // silently become permanent on unproven provenance.
    const confidence: 'hard' | 'soft' = ipCheck ? (ipCheck.ban_confidence ?? 'soft') : 'hard';
    const q = this.config.auto_ban?.quarantine;
    const quarantineEnabled = q?.enabled !== false; // default on
    const isSoft = confidence === 'soft' && quarantineEnabled;

    const reason = this.config.auto_ban?.ban_reason || 'VPN/Proxy detected. Appeal: @WizanthiContactBot';
    const banMinutes = isSoft
      ? (q?.duration_minutes ?? 60)
      : (this.config.auto_ban?.ban_duration_minutes || 0);

    try {
      await this.rconService.ban(player.ip, banMinutes, reason);
      this.bannedIps.add(player.ip);
      this.logger.warn(`${isSoft ? 'QUARANTINED' : 'AUTO-BANNED'}: ${player.nickname} (${player.ip}) [${isSoft ? banMinutes + 'min, pending review' : 'permanent'}]`);

      // Every soft quarantine is handed to the re-verification worker: it
      // re-runs the FULL pipeline after a few minutes and either escalates
      // (full ban - detection preserved) or auto-reverts (FP averted).
      if (isSoft && this.quarantineReviewer) {
        this.quarantineReviewer.enqueue({
          ip: player.ip, nickname: player.nickname, banMinutes,
          result: ipCheck, bannedAt: Date.now(),
        });
      }

      const tracked = this.players.get(player.id) || {
        id: player.id, nickname: player.nickname, clan: player.clan || '', ip: player.ip,
        first_seen: new Date().toISOString(), last_seen: new Date().toISOString(), sessions: 1,
        flags: { is_whitelisted: false, is_blacklisted: !isSoft, is_vpn: false, is_proxy: false, is_suspicious: true, is_trusted: false },
        ip_check: ipCheck
      };
      const effectiveCheck: IpCheckResult = ipCheck || {
        ip: player.ip, is_vpn: false, is_proxy: false, is_tor: false, is_hosting: false, is_datacenter: false,
        risk_score: 100, threat_level: 'critical', checked_at: new Date().toISOString(), cached: false
      };

      if (isSoft && q?.review_webhook !== false) {
        await this.webhookService.sendReviewAlert(tracked, effectiveCheck, banMinutes);
      } else {
        await this.webhookService.sendAutoBan(tracked, effectiveCheck);
      }
    } catch (error) {
      this.logger.error(`Failed to auto-ban ${player.nickname}`, error);
    }
  }

  // Called by AdminCommandService the instant `$sudo antivpn enable 1` flips
  // the master switch back on. While it was off, joins were still checked
  // and flagged in real time (see the isAntiVpnEnabled() gates above) but
  // every ban was skipped - so any of the (possibly dozens of) bots that
  // swarmed in during that window are sitting on the server, already
  // known-bad, just unbanned. This sweeps every currently tracked flagged
  // player plus every known custom-ban match and bans/re-applies them in
  // the same bounded-parallel batches the join checks use, so 50 already-
  // identified bots get cleaned up in one shot instead of trickling out on
  // the next leave/rejoin or 30s scan tick.
  async banAllPendingSuspicious(): Promise<{ banned: number; total: number }> {
    const targets = this.getAllPlayers().filter(p =>
      (p.flags.is_suspicious || p.flags.is_blacklisted) &&
      !this.bannedIps.has(p.ip) &&
      !this.listManager.isWhitelisted(p.ip)
    );

    if (targets.length === 0) return { banned: 0, total: 0 };

    this.logger.warn(`AntiVPN re-enabled: acting on ${targets.length} player(s) already flagged while paused`);

    let banned = 0;
    for (let i = 0; i < targets.length; i += this.maxParallelChecks) {
      const batch = targets.slice(i, i + this.maxParallelChecks);
      const results = await Promise.allSettled(batch.map(async (p) => {
        if (this.customBanManager.isCustomBanned(p.ip)) {
          const ok = await this.customBanManager.executeBan(p.ip);
          if (ok) this.bannedIps.add(p.ip);
          return ok;
        }
        if (this.getMode() === 'autoban' && this.isAutoBanEnabled()) {
          await this.autoBan(
            { id: p.id, nickname: p.nickname, clan: p.clan, ip: p.ip, score: 0, latency: 0 },
            p.ip_check
          );
          return this.bannedIps.has(p.ip);
        }
        return false;
      }));
      banned += results.filter(r => r.status === 'fulfilled' && r.value).length;
      if (i + this.maxParallelChecks < targets.length) await this.delay(100);
    }

    this.logger.warn(`AntiVPN re-enable sweep complete: ${banned}/${targets.length} banned`);
    return { banned, total: targets.length };
  }

  private trackPlayer(sp: StatusPlayer, flags: TrackedPlayer['flags'], ipCheck?: IpCheckResult): TrackedPlayer {
    const ex = this.players.get(sp.id);
    const pending = this.pendingNames.get(sp.id);
    if (pending) this.pendingNames.delete(sp.id);
    // Name priority: a real name on this update > a name the batched
    // resolver parked while the check was in flight > whatever we already
    // had > the placeholder itself.
    const nickname = !this.isPlaceholderName(sp.nickname)
      ? sp.nickname
      : (pending?.nickname || ex?.nickname || sp.nickname);
    const clan = sp.clan || pending?.clan || ex?.clan || '';
    const player: TrackedPlayer = {
      id: sp.id, nickname, clan, ip: sp.ip,
      first_seen: ex?.first_seen || new Date().toISOString(),
      last_seen: new Date().toISOString(),
      sessions: ex ? ex.sessions : 1, flags, ip_check: ipCheck
    };
    this.players.set(sp.id, player);
    if (!ex) this.leaveCheckedIds.delete(sp.id);
    return player;
  }

  private delay(ms: number): Promise<void> { return new Promise(r => setTimeout(r, ms)); }

  private isPlaceholderName(nickname: string): boolean {
    return !nickname || nickname === 'Unknown' || /^Player_\d+$/i.test(nickname) || /^Left_Player_\d+$/i.test(nickname);
  }

  private isGeneratedPlayerName(nickname: string): boolean {
    return /^Player_\d+$/i.test(nickname) || /^Left_Player_\d+$/i.test(nickname);
  }

  getPlayer(id: number): TrackedPlayer | undefined { return this.players.get(id); }
  getAllPlayers(): TrackedPlayer[] { return Array.from(this.players.values()); }
  getSuspiciousPlayers(): TrackedPlayer[] { return this.getAllPlayers().filter(p => p.flags.is_suspicious); }

  getStats(): { total: number; whitelisted: number; blacklisted: number; suspicious: number; clean: number; banned: number; mode: string; customBans: number; quarantine?: { reviewed: number; escalated: number; upheld: number; reverted: number; pending: number } } {
    const all = this.getAllPlayers();
    const customStats = this.customBanManager.getStats();
    return {
      total: all.length,
      whitelisted: all.filter(p => this.listManager.isWhitelisted(p.ip)).length,
      blacklisted: all.filter(p => this.listManager.isBlacklisted(p.ip)).length,
      suspicious: all.filter(p => p.flags.is_suspicious).length,
      clean: all.filter(p => !p.flags.is_suspicious && !this.listManager.isBlacklisted(p.ip)).length,
      banned: this.bannedIps.size,
      mode: this.getMode(),
      customBans: customStats.enabled,
      // FP telemetry: how often quarantines get escalated (detection stood
      // up) vs reverted (FP averted) - the live measure of the soft-ban
      // pipeline's false-positive rate.
      quarantine: this.quarantineReviewer?.getStats()
    };
  }

  clear(): void {
    this.players.clear();
    this.leaveCheckedIds.clear();
    // Drop any checks still waiting on a slot - they belong to the
    // session being torn down; a reconnect re-scans everyone online anyway.
    this.checkQueue = [];
    this.activeChecks = 0;
    this.pendingNames.clear();
    // bannedIps used to leak across a full session/restart (it's only a
    // re-ban dedup guard, and its members are re-established from the
    // blacklist/custombans on reconnect anyway).
    this.bannedIps.clear();
  }
}