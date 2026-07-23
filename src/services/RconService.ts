// src/services/RconService.ts
import * as net from 'net';
import { StatusResponse, StatusPlayer, RconAuthStatus } from '../types';
import { Logger } from '../utils/Logger';

// Extracts the bare IP out of a "host:port" (IPv4) or "[host]:port" (IPv6,
// bracketed - DDNet's own net_addr_str always brackets IPv6 for exactly
// this reason) address string as reported by RCON status/join lines.
// Previously this was a bare `.split(':')[0]`, which is correct for IPv4
// but silently mangles every IPv6 address (multiple colons) down to just
// its first hextet - every downstream check (whitelist/blacklist/ban/
// dataset lookup) for an IPv6 player was therefore operating on garbage.
export function parseAddrHost(addr: string): string {
  const trimmed = addr.trim();
  if (trimmed.startsWith('[')) {
    const end = trimmed.indexOf(']');
    if (end !== -1) return trimmed.slice(1, end);
  }
  const lastColon = trimmed.lastIndexOf(':');
  // A bare (unbracketed) IPv6 address has more than one colon - only strip
  // a trailing ":port" when there's exactly one colon (IPv4) or the value
  // is already known to be bracketed (handled above). Otherwise the whole
  // string *is* the address (or malformed input we shouldn't mangle
  // further) and is returned as-is.
  if (lastColon === -1) return trimmed;
  const colonCount = (trimmed.match(/:/g) || []).length;
  return colonCount === 1 ? trimmed.slice(0, lastColon) : trimmed;
}

// Strict validation before any IP is interpolated into an RCON console
// command string - net.isIP returns 0 for anything that isn't a
// syntactically valid IPv4/IPv6 address, which rules out whitespace,
// quotes, semicolons, newlines etc. that DDNet's console (which supports
// ';'-chained commands, same as a shell) would otherwise interpret as
// additional commands.
export function isValidIp(ip: string): boolean {
  return net.isIP(ip) !== 0;
}

// DDNet's console tokenizer treats ';' as a command separator and '"' as a
// string-argument delimiter, so a `reason` string that reaches an RCON
// command unescaped could terminate the intended quoted argument early and
// have the rest of the line interpreted as further console commands (RCON
// command injection). Every character that has any special meaning to the
// console tokenizer is stripped rather than escaped, since DDNet's
// escaping rules for embedded quotes aren't part of this project's
// contract to get exactly right - dropping them is always safe for a ban
// reason string, which is display text, not something that needs to round
// -trip byte-for-byte.
export function sanitizeRconArg(value: string): string {
  return value.replace(/["\\;\r\n]/g, '').slice(0, 256);
}

// RCON service - handles server communication - singleton pattern
export class RconService {
  private client: any;
  private logger: Logger;
  private rconLines: string[] = [];
  private isAuthenticated: boolean = false;
  private authPromise: Promise<void> | null = null;
  private authResolve: (() => void) | null = null;
  private onPlayerJoinCallback: ((player: StatusPlayer) => void) | null = null;
  private onPlayerLeaveCallback: ((clientId: number) => void) | null = null;
  private pendingJoins: Map<number, string> = new Map();
  private commandQueue: Promise<unknown> = Promise.resolve();
  // Batched name resolution (see scheduleNameResolution): one debounced
  // status round-trip serves every pending joiner instead of one per join.
  private nameResolveTimer: NodeJS.Timeout | null = null;
  private nameResolveAttempts: number = 0;
  private nameResolveRunning: boolean = false;

  constructor(client: any) {
    this.client = client;
    this.logger = Logger.getInstance();
    this.setupRconListener();
  }

  private setupRconListener(): void {
    this.client.rcon.on('rcon_line', (line: string) => {
      this.rconLines.push(line);

      const enterMatch = line.match(/player has entered the game\. ClientId=(\d+) addr=([^\s]+)/);
      if (enterMatch) {
        const clientId = parseInt(enterMatch[1]);
        const ip = parseAddrHost(enterMatch[2]);

        this.logger.info(`Player joined: ID=${clientId}, IP=${ip}`);
        this.pendingJoins.set(clientId, ip);
        // Hand the joiner to the check pipeline IMMEDIATELY - the VPN check
        // and the ban are keyed on the IP alone, and the IP is right here in
        // the join line. Waiting on name resolution before checking is what
        // used to let a swarm play for minutes before anything happened. The
        // real nickname arrives via the batched resolver below and gets
        // patched into tracking (the session layer dedupes by IP, so this
        // second callback never triggers a second check).
        if (this.onPlayerJoinCallback) {
          this.onPlayerJoinCallback({ id: clientId, nickname: 'Unknown', clan: '', ip, score: 0, latency: 0 });
        }
        this.scheduleNameResolution();
      }

      const leaveMatch = line.match(/player has left the game\. ClientId=(\d+)/);
      if (leaveMatch) {
        const clientId = parseInt(leaveMatch[1]);
        this.logger.info(`Player left: ID=${clientId}`);

        if (this.onPlayerLeaveCallback) {
          this.onPlayerLeaveCallback(clientId);
        }

        this.pendingJoins.delete(clientId);
      }

      const chatEnterMatch = line.match(/I chat: \*\*\* '(.+?)' entered and joined the game/);
      if (chatEnterMatch && this.pendingJoins.size === 1) {
        const nickname = chatEnterMatch[1];
        const [cid, ip] = this.pendingJoins.entries().next().value as [number, string];

        this.logger.info(`Chat join: ${nickname}`);
        this.pendingJoins.delete(cid);

        if (this.onPlayerJoinCallback) {
          this.onPlayerJoinCallback({
            id: cid,
            nickname,
            clan: '',
            ip,
            score: 0,
            latency: 0
          });
        }
      }
    });

    this.client.rcon.on('rcon_auth_status', (status: RconAuthStatus) => {
      this.isAuthenticated = true;
      this.logger.info(`RCON authenticated - Level: ${status.AuthLevel}`);
      if (this.authResolve) {
        this.authResolve();
        this.authResolve = null;
      }
    });
  }

  // Batched name resolution. The old per-join tryGetPlayerInfo() spawned an
  // independent retry loop (up to 5 `status` round-trips, each ~2s on the
  // serialized command queue) PER JOIN - a 30-bot swarm therefore queued up
  // to 150 status commands behind each other, wedging the RCON pipeline for
  // minutes and delaying every joiner's IP check (and ban) by that much.
  // Instead, joins are collected in pendingJoins and a single debounced pass
  // resolves ALL of them with ONE status command, however many joined.
  private scheduleNameResolution(): void {
    // A pass is already scheduled or executing - it (or its retry) will pick
    // up this join too, since passes read pendingJoins live. Scheduling a
    // second concurrent pass would just double the status traffic.
    if (this.nameResolveTimer || this.nameResolveRunning) return;
    this.nameResolveAttempts = 0;
    this.nameResolveTimer = setTimeout(() => void this.resolvePendingNames(), 1000);
  }

  private async resolvePendingNames(): Promise<void> {
    this.nameResolveTimer = null;
    if (this.pendingJoins.size === 0) return;
    this.nameResolveRunning = true;
    try {
      await this.runNameResolutionPass();
    } finally {
      this.nameResolveRunning = false;
    }
  }

  private async runNameResolutionPass(): Promise<void> {
    this.nameResolveAttempts++;

    let players: StatusPlayer[] = [];
    try {
      players = (await this.executeStatus()).players;
    } catch (e) {
      // fall through - retry/flush logic below handles the empty list
    }
    const byId = new Map(players.map(p => [p.id, p]));

    for (const [clientId, ip] of [...this.pendingJoins]) {
      const player = byId.get(clientId);
      if (player && player.nickname && player.nickname !== 'Unknown') {
        this.logger.info(`Got name: ${player.nickname} (ID=${clientId})`);
        this.pendingJoins.delete(clientId);
        // Re-announce with the real name so tracking picks it up; the check
        // itself already started from the join-line callback, and the
        // session layer's IP dedupe guarantees no second check fires.
        // Trust the join line's IP over the status parse for safety.
        if (this.onPlayerJoinCallback) this.onPlayerJoinCallback({ ...player, ip });
      } else if (!player && this.nameResolveAttempts >= 2) {
        // Joined and left between passes - the check already ran from the
        // join-line callback, so there is nothing left to resolve.
        this.pendingJoins.delete(clientId);
      }
    }

    if (this.pendingJoins.size === 0) return;

    if (this.nameResolveAttempts >= 5) {
      // Names never resolved (e.g. server too busy to answer status during a
      // swarm). Not a problem for enforcement: every joiner was already
      // checked (and banned if flagged) from the join-line callback - the
      // nickname is display-only. Just stop polling.
      this.logger.warn(`Gave up resolving names for ${this.pendingJoins.size} joiner(s) - their IP checks already ran`);
      this.pendingJoins.clear();
      return;
    }

    this.nameResolveTimer = setTimeout(() => void this.resolvePendingNames(), 2000);
  }

  onPlayerJoin(callback: (player: StatusPlayer) => void): void {
    this.onPlayerJoinCallback = callback;
  }

  onPlayerLeave(callback: (clientId: number) => void): void {
    this.onPlayerLeaveCallback = callback;
  }

  async login(password: string, username?: string): Promise<void> {
    // Reset first: after a reconnect, a stale `true` left over from the
    // previous session would make the post-timeout `if (!isAuthenticated)`
    // guard below pass even if this re-auth never actually succeeded,
    // silently masking a failed re-auth.
    this.isAuthenticated = false;
    this.authPromise = new Promise<void>((resolve) => {
      this.authResolve = resolve;
    });

    try {
      if (username) {
        this.client.rcon.auth(username, password);
      } else {
        this.client.rcon.auth(password);
      }

      const timeout = setTimeout(() => {
        if (this.authResolve) {
          this.authResolve();
          this.authResolve = null;
        }
      }, 10000);

      await this.authPromise;
      clearTimeout(timeout);

      if (!this.isAuthenticated) throw new Error('RCON authentication failed');
    } catch (error) {
      this.logger.error('RCON login error', error);
      throw error;
    }
  }

  async execute(command: string): Promise<string[]> {
    const run = (): Promise<string[]> => {
      this.rconLines = [];
      return new Promise((resolve) => {
        const timeout = setTimeout(() => resolve([...this.rconLines]), 3000);
        try {
          this.client.rcon.rcon(command);
          setTimeout(() => {
            clearTimeout(timeout);
            resolve([...this.rconLines]);
          }, command === 'status' ? 2000 : 1000);
        } catch (error) {
          clearTimeout(timeout);
          resolve([]);
        }
      });
    };

    const result = this.commandQueue.then(run, run);
    this.commandQueue = result.then(() => undefined, () => undefined);
    return result;
  }

  async executeStatus(): Promise<StatusResponse> {
    const lines = await this.execute('status');
    const players = this.parseStatusOutput(lines);
    return { players, raw: lines.join('\n'), timestamp: new Date().toISOString() };
  }

  // The single, safe way to issue a "ban" console command - every call site
  // in this project (PlayerTracker's auto-ban, CustomBanManager) should go
  // through this instead of building the command string itself, so the
  // validation/sanitization only has to be right in one place. Throws
  // rather than silently no-op'ing on an invalid IP so a caller can log/
  // alert on it - an invalid IP reaching here means something upstream is
  // already broken and deserves attention, not a quietly-dropped ban.
  async ban(ip: string, minutes: number, reason: string): Promise<string[]> {
    if (!isValidIp(ip)) {
      throw new Error(`RconService.ban: refusing to build a ban command for invalid IP ${JSON.stringify(ip)}`);
    }
    const safeMinutes = Number.isFinite(minutes) && minutes >= 0 ? Math.floor(minutes) : 0;
    const safeReason = sanitizeRconArg(reason || '');
    // Bans are fired at the socket immediately instead of going through
    // execute()'s serialized commandQueue. That queue exists so commands
    // that READ console output (status) don't interleave their rcon_line
    // captures - but a ban never reads anything back, and queueing it
    // behind a 1s-per-command pipeline meant a 30-player VPN swarm took
    // ~30s to fully ban (the last joiner played for half a minute). With
    // the direct send, 30 parallel detections produce 30 bans in the same
    // instant. Any ban confirmation lines the server echoes land in a
    // concurrent status capture harmlessly - parseStatusOutput drops every
    // line without id/addr/name fields.
    this.client.rcon.rcon(`ban ${ip} ${safeMinutes} "${safeReason}"`);
    return [];
  }

  // Counterpart to ban() above, used by the quarantine re-verification
  // worker (QuarantineReviewer) when a soft quarantine turns out not to be
  // corroborated by a full re-check - same validation posture: refuse
  // loudly on an invalid IP rather than silently skipping the revert.
  async unban(ip: string): Promise<string[]> {
    if (!isValidIp(ip)) {
      throw new Error(`RconService.unban: refusing to build an unban command for invalid IP ${JSON.stringify(ip)}`);
    }
    // Same direct-send rationale as ban(): unban reads nothing back, so it
    // doesn't need the serialized command queue.
    this.client.rcon.rcon(`unban ${ip}`);
    return [];
  }

  private parseStatusOutput(lines: string[]): StatusPlayer[] {
    const players: StatusPlayer[] = [];

    for (const line of lines) {
      if (!line.trim() ||
          line.includes('rcon=') ||
          line.includes('player has entered') ||
          line.includes('player has left') ||
          line.includes('I chat:') ||
          line.includes('I game:') ||
          line.includes('I ddnet:')) {
        continue;
      }

      const fields = this.parseStatusFields(line);
      const id = fields.get('id');
      const addr = fields.get('addr');
      const name = fields.get('name');

      if (id && addr && name) {
        players.push({
          id: parseInt(id),
          score: parseInt(fields.get('score') || '0') || 0,
          latency: parseInt(fields.get('latency') || '0') || 0,
          nickname: name,
          clan: fields.get('clan') || '',
          ip: parseAddrHost(addr)
        });
      }
    }

    return players.filter((p, i, self) => self.findIndex(t => t.id === p.id) === i);
  }

  private parseStatusFields(line: string): Map<string, string> {
    const fields = new Map<string, string>();
    const regex = /(\w+)=('(?:\\'|[^'])*'|[^\s]+)/g;
    let match: RegExpExecArray | null;

    while ((match = regex.exec(line)) !== null) {
      const rawValue = match[2];
      const value = rawValue.startsWith("'") && rawValue.endsWith("'")
        ? rawValue.slice(1, -1).replace(/\\'/g, "'")
        : rawValue;
      fields.set(match[1], value);
    }

    return fields;
  }
}