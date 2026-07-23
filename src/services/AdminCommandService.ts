// src/services/AdminCommandService.ts
//
// In-game admin commands over chat/whisper, gated by the operator-managed
// IP whitelist in config.json -> admin.whitelisted_ips. The session layer
// already remembers every player's join IP (SessionManager.playerIpHistory);
// this service resolves the chatting client_id back to that IP and only
// obeys commands from whitelisted addresses.
//
// Command form (default prefix '$', configurable via admin.prefix):
//   $sudo antivpn <setting> ["value"]   - read/change a config.json setting
//   $sudo antivpn enable 1/0            - master switch: 0 pauses all checks/
//                                         bans (bot stays connected + keeps
//                                         its hourly reconnect), 1 resumes.
//                                         Persisted to config.json ->
//                                         antivpn.enabled, so the choice
//                                         survives rejoins AND restarts.
//   $sudo antivpn whitelist <ip>        - whisper-only: whitelist an IP
//   $sudo antivpn blacklist <ip>        - whisper-only: blacklist + ban an IP
//   $sudo antivpn ban <id>              - manually ban the player with that
//                                         client id using the configured
//                                         auto_ban.ban_reason/duration.
//                                         Allowed from BOTH public chat and
//                                         /w - the argument is a client id,
//                                         not an IP, so nothing private ever
//                                         appears in chat.
//
// Response-channel rules (all responses go out as RCON commands):
//   - `$antivpn ...` (missing sudo) or any attempt from a non-whitelisted
//     IP: `mod_alert {id} ✦ Access denied.✦` - never `say`, so the denial
//     leaks nothing to public chat.
//   - whitelist/blacklist typed in PUBLIC chat by a whitelisted IP:
//     `mod_alert {id} ✦ Use /w for whitelist/blacklist✦` (never `say` -
//     these commands carry IPs, which are private info).
//   - whitelist/blacklist via whisper: executed, reply via `mod_alert {id}`.
//   - regular (config) commands: executed from either channel; reply via
//     `say` when asked in public chat, `mod_alert {id}` when whispered.
//
// Config commands can touch every section EXCEPT server, discord, bot,
// apis, storage, datasets and admin itself - so connection credentials,
// API keys, webhooks and the admin whitelist can never be read or changed
// from in-game chat.
import { Logger } from '../utils/Logger';
import { ConfigManager } from '../config/ConfigManager';
import { ListManager } from './ListManager';
import { RconService, isValidIp } from './RconService';
import { AppConfig } from '../types';
import { PlayerTracker } from '../core/PlayerTracker';
import { CustomBanManager } from './CustomBanManager';

// Sections of config.json that in-game commands may read/write. Everything
// else (server/rcon credentials, discord webhooks, API keys, storage
// passwords, datasets, the admin whitelist itself) is off-limits.
const EDITABLE_SECTIONS = ['ipcheck', 'monitoring', 'logs', 'impossible_travel', 'auto_ban', 'detection'];

// Extra defense in depth: even inside an editable section, never expose a
// path containing one of these (nothing sensitive lives there today, but a
// future config addition shouldn't silently become chattable). Fragments
// match anywhere inside a path segment; exacts must equal a whole segment
// (so e.g. detection.weights.hosting_asn is NOT blocked by 'host').
const FORBIDDEN_SEGMENT_FRAGMENTS = ['api_key', 'password', 'webhook', 'rcon'];
const FORBIDDEN_SEGMENTS = ['host', 'port'];

// Commands that carry IP addresses and are therefore whisper-only.
const PRIVATE_COMMANDS = new Set(['whitelist', 'blacklist', 'custom_ban', 'custom_ban_remove']);

export class AdminCommandService {
  private logger: Logger;
  private config: AppConfig;
  private configManager: ConfigManager;
  private listManager: ListManager;
  private rconService: RconService;
  private resolveIp: (clientId: number) => string | undefined;

  constructor(
    config: AppConfig,
    rconService: RconService,
    resolveIp: (clientId: number) => string | undefined
  ) {
    this.logger = Logger.getInstance();
    this.config = config;
    this.configManager = ConfigManager.getInstance();
    this.listManager = ListManager.getInstance();
    this.rconService = rconService;
    this.resolveIp = resolveIp;
  }

  // Entry point - wired to the client's 'message' event by SessionManager.
  // isWhisper is true for /w messages addressed to the bot (DDNet delivers
  // those as SV_CHAT with team >= 2), false for public/team chat.
  handleChatMessage(clientId: number, message: string, isWhisper: boolean): void {
    const prefix = this.config.admin?.prefix || '$';
    const trimmed = (message || '').trim();
    if (!trimmed.startsWith(prefix)) return;

    const body = trimmed.slice(prefix.length).trim();

    // `$antivpn ...` without sudo is always denied, whitelisted or not.
    if (/^antivpn\b/i.test(body)) {
      this.modAlert(clientId, '✦ Access denied.✦');
      return;
    }

    const sudoMatch = body.match(/^sudo\s+antivpn\b\s*([\s\S]*)$/i);
    if (!sudoMatch) return; // some other $-prefixed chatter - not ours

    const ip = this.resolveIp(clientId);
    if (!ip || !this.isAdminIp(ip)) {
      this.logger.warn(`Admin command denied for client ${clientId} (ip=${ip || 'unknown'}): ${trimmed}`);
      this.modAlert(clientId, '✦ Access denied.✦');
      return;
    }

    const rest = sudoMatch[1].trim();
    if (!rest) {
      this.reply(clientId, isWhisper, `✦ Usage: ${prefix}sudo antivpn <setting> ["value"] | ban <id> | whitelist <ip> | blacklist <ip>✦`);
      return;
    }

    const spaceIdx = rest.search(/\s/);
    const command = (spaceIdx === -1 ? rest : rest.slice(0, spaceIdx)).toLowerCase();
    const arg = spaceIdx === -1 ? '' : rest.slice(spaceIdx).trim();

    // Master switch - handled ahead of the generic config path because it
    // lives in the `antivpn` section, which is deliberately NOT in
    // EDITABLE_SECTIONS (only this dedicated command may touch it).
    if (command === 'enable') {
      this.reply(clientId, isWhisper, this.execEnable(arg));
      return;
    }

    // Manual ban by client id. Allowed from both public chat and /w - the
    // argument is a client id, not an IP, and the reply never echoes the
    // resolved IP, so nothing private can leak into public chat.
    if (command === 'ban') {
      this.reply(clientId, isWhisper, this.execBan(arg));
      return;
    }

    if (PRIVATE_COMMANDS.has(command)) {
      if (!isWhisper) {
        // Whitelisted admin used a private command in public chat - point
        // them at /w via mod_alert, never via say (per spec: no `say` here).
        this.modAlert(clientId, '✦ Use /w for whitelist/blacklist✦');
        return;
      }
      let result: string;
      if (command === 'whitelist') result = this.execWhitelist(arg);
      else if (command === 'blacklist') result = this.execBlacklist(arg);
      else if (command === 'custom_ban') result = this.execCustomBan(arg);
      else result = this.execCustomBanRemove(arg);
      this.modAlert(clientId, result);
      return;
    }

    const result = this.execConfigCommand(command, arg);
    this.reply(clientId, isWhisper, result);
  }

  private isAdminIp(ip: string): boolean {
    const list = this.config.admin?.whitelisted_ips || [];
    return list.includes(ip);
  }

  // --- responses ------------------------------------------------------------

  // Regular-command replies: `say` for public chat, `mod_alert` for whispers.
  private reply(clientId: number, isWhisper: boolean, text: string): void {
    if (isWhisper) this.modAlert(clientId, text);
    else this.say(text);
  }

  private say(text: string): void {
    void this.rconService.execute(`say ${this.sanitizeForRcon(text)}`);
  }

  private modAlert(clientId: number, text: string): void {
    if (!Number.isInteger(clientId) || clientId < 0) return;
    void this.rconService.execute(`mod_alert ${clientId} ${this.sanitizeForRcon(text)}`);
  }

  // Everything echoed back originated in player chat, so strip the
  // characters DDNet's console tokenizer treats specially (';' chains
  // commands) before interpolating into an RCON line.
  private sanitizeForRcon(text: string): string {
    return text.replace(/[;\r\n]/g, ' ').slice(0, 240);
  }

  // --- whitelist / blacklist (whisper-only) ---------------------------------

  private execWhitelist(arg: string): string {
    const ip = this.parseIpArg(arg);
    if (!ip) return '✦ Invalid IP✦';
    // Lift any standing dynamic blacklist entry + active ban, then trust.
    this.listManager.removeFromBlacklist(ip);
    this.listManager.addToWhitelist(ip, 'Admin chat command');
    if (isValidIp(ip)) {
      this.rconService.unban(ip).catch(() => { /* not banned - fine */ });
    }
    this.logger.info(`Admin command: whitelisted ${ip}`);
    return `✦ Whitelisted ${ip}✦`;
  }

  private execBlacklist(arg: string): string {
    const ip = this.parseIpArg(arg);
    if (!ip) return '✦ Invalid IP✦';
    this.listManager.addToBlacklist(ip, 'Admin chat command', 'AdminCommand');
    if (isValidIp(ip)) {
      const minutes = this.config.auto_ban?.ban_duration_minutes || 0;
      const reason = this.config.auto_ban?.ban_reason || 'VPN/Proxy detected';
      this.rconService.ban(ip, minutes, reason).catch((e) => this.logger.error('Admin blacklist ban failed', e));
    }

    this.logger.warn(`Admin command: blacklisted ${ip}`);
    return `Blacklisted ${ip}`;
  }
  // Duration is in whole minutes, matching DDNet's RCON `ban` command. A
  // zero duration is permanent; the reason consumes the rest of the whisper.
  private execCustomBan(arg: string): string {
    const match = arg.match(/^(\S+)\s+(\d+)\s+([\s\S]*\S)$/);
    if (!match) return 'Usage: custom_ban <ip> <minutes> <reason>';

    const ip = match[1];
    const durationMinutes = Number(match[2]);
    if (!isValidIp(ip)) return 'Invalid IP';
    if (!Number.isSafeInteger(durationMinutes)) return 'Invalid ban duration';

    let reason = match[3].trim();
    if (reason.length >= 2 && reason.startsWith('"') && reason.endsWith('"')) {
      reason = reason.slice(1, -1);
    }
    if (!reason) return 'Ban reason is required';

    CustomBanManager.getInstance().addBan(ip, reason, durationMinutes);
    this.logger.warn(`Admin command: added custom ban for ${ip} (${durationMinutes}min)`);
    return `Custom ban added for ${ip} (${durationMinutes === 0 ? 'permanent' : durationMinutes + 'min'})`;
  }

  private execCustomBanRemove(arg: string): string {
    const ip = arg.trim();
    if (!isValidIp(ip)) return 'Invalid IP';

    CustomBanManager.getInstance().removeBan(ip);
    this.logger.info(`Admin command: removed custom ban for ${ip}`);
    return `Custom ban removed for ${ip}`;
    this.logger.warn(`Admin command: blacklisted ${ip}`);
    return `✦ Blacklisted ${ip}✦`;
  }

  // Accepts a bare IPv4/IPv6 address or an IPv4 CIDR. Returns null on
  // anything else - the value gets interpolated into RCON commands and
  // stored in the lists, so it must be strictly validated.
  private parseIpArg(arg: string): string | null {
    const value = arg.trim();
    if (!value) return null;
    if (isValidIp(value)) return value;
    const cidrMatch = value.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/);
    if (cidrMatch && isValidIp(cidrMatch[1]) && parseInt(cidrMatch[2], 10) <= 32) return value;
    return null;
  }

  // --- manual ban ($sudo antivpn ban <id>) ----------------------------------

  // Bans the player currently connected under the given client id, using the
  // same duration/reason the auto-ban path uses. The target's IP is resolved
  // from the session layer's join-IP map (same source the admin auth check
  // uses) and is deliberately never echoed back - replies may go to public
  // chat.
  private execBan(arg: string): string {
    if (!/^\d{1,3}$/.test(arg)) return '✦ Usage: ban <id>✦';
    const targetId = parseInt(arg, 10);
    const targetIp = this.resolveIp(targetId);
    if (!targetIp) return `✦ Unknown player id ${targetId}✦`;
    if (!isValidIp(targetIp)) return `✦ Cannot ban id ${targetId}: bad address✦`;
    if (this.listManager.isWhitelisted(targetIp)) {
      return `✦ Player ${targetId} is whitelisted✦`;
    }
    const minutes = this.config.auto_ban?.ban_duration_minutes || 0;
    const reason = this.config.auto_ban?.ban_reason || 'VPN/Proxy detected';
    this.rconService.ban(targetIp, minutes, reason).catch((e) => this.logger.error('Admin manual ban failed', e));
    this.logger.warn(`Admin command: manually banned client ${targetId} (ip=${targetIp})`);
    return `✦ Banned player ${targetId}✦`;
  }

  // --- master switch ($sudo antivpn enable 1/0) -----------------------------

  // Pauses/resumes the entire detection pipeline. Persisted to config.json
  // (antivpn.enabled) via ConfigManager.setValue, so the state survives the
  // hourly reconnect and full restarts. The bot itself stays connected and
  // keeps reconnecting either way - the hot paths (PlayerTracker /
  // SessionManager) consult ConfigManager.isAntiVpnEnabled() live.
  private execEnable(arg: string): string {
    if (!arg) {
      return `✦ AntiVPN is ${this.configManager.isAntiVpnEnabled() ? 'ENABLED' : 'DISABLED'}✦`;
    }
    if (arg !== '1' && arg !== '0') return '✦ Usage: enable 1/0✦';

    const enable = arg === '1';
    if (enable === this.configManager.isAntiVpnEnabled()) {
      return `✦ AntiVPN already ${enable ? 'ENABLED' : 'DISABLED'}✦`;
    }
    try {
      this.configManager.setValue('antivpn.enabled', enable);
    } catch (e) {
      this.logger.error('Admin command: failed to save antivpn.enabled', e);
      return '✦ Failed to save config✦';
    }
    this.logger.warn(`Admin command: AntiVPN ${enable ? 'ENABLED' : 'DISABLED'}`);

    // 0 -> 1 transition: while disabled, joins/leaves/scans kept checking and
    // flagging players in real time but every ban was skipped (see the
    // isAntiVpnEnabled() gates in PlayerTracker/CustomBanManager) - so
    // whoever swarmed in during that window (could be dozens of bots) is
    // sitting on the server already known-bad, just unbanned. Sweep and act
    // on all of them immediately, in parallel, rather than waiting for the
    // next leave/rejoin or 30s scan tick. Fire-and-forget: the chat reply
    // shouldn't block on however many players need banning.
    if (enable) {
      PlayerTracker.getInstance().banAllPendingSuspicious()
        .catch((e) => this.logger.error('Post-enable ban sweep failed', e));
      CustomBanManager.getInstance().executeAllBans()
        .catch((e) => this.logger.error('Post-enable custom-ban sync failed', e));
    }

    return `✦ AntiVPN ${enable ? 'ENABLED' : 'DISABLED'}✦`;
  }

  // --- config get/set -------------------------------------------------------

  private execConfigCommand(command: string, arg: string): string {
    if (!/^[a-z0-9_.]+$/i.test(command)) return '✦ Unknown command.✦';

    const path = this.resolvePath(command);
    if (path === null) return `✦ Unknown setting: ${command}✦`;
    if (Array.isArray(path)) {
      return `✦ Ambiguous setting, use full path: ${path.slice(0, 4).join(', ')}✦`;
    }

    const current = this.configManager.getValue(path);

    // No argument -> show the current value. For string settings the value
    // must be quoted to count as a set (`$sudo antivpn ban_reason "x"`);
    // an unquoted trailer on a string setting also just shows the value.
    const isQuoted = arg.length >= 2 && arg.startsWith('"') && arg.endsWith('"');
    if (!arg || (typeof current === 'string' && !isQuoted)) {
      return `✦ Value=${this.formatValue(current)}✦`;
    }

    const parsed = this.parseValueArg(arg);
    if (parsed === undefined) return `✦ Invalid value✦`;

    // Keep the stored type stable: a number stays a number, a boolean a
    // boolean, etc. - a typo'd value must not silently corrupt the config.
    const typeError = this.checkType(current, parsed);
    if (typeError) return `✦ Invalid value for ${command} (expected ${typeError})✦`;

    try {
      this.configManager.setValue(path, parsed);
    } catch (e) {
      this.logger.error(`Admin command: failed to save config for ${path}`, e);
      return '✦ Failed to save config✦';
    }
    this.logger.info(`Admin command: config ${path} changed to ${JSON.stringify(parsed)}`);
    const display = typeof parsed === 'string' ? `"${parsed}"` : this.formatValue(parsed);
    return `✦ ${command} changed to ${display}✦`;
  }

  // Resolves a command name to a config path. A dotted name is used as-is
  // (after section/exists checks); a bare name is searched across all
  // editable sections. Returns the path, an array of candidates when
  // ambiguous, or null when unknown/forbidden.
  private resolvePath(command: string): string | string[] | null {
    const isForbidden = (p: string) =>
      p.toLowerCase().split('.').some((seg) =>
        FORBIDDEN_SEGMENTS.includes(seg) ||
        FORBIDDEN_SEGMENT_FRAGMENTS.some((frag) => seg.includes(frag)));

    if (command.includes('.')) {
      const section = command.split('.')[0];
      if (!EDITABLE_SECTIONS.includes(section)) return null;
      if (isForbidden(command)) return null;
      return this.configManager.getValue(command) === undefined ? null : command;
    }

    const matches: string[] = [];
    const walk = (obj: any, prefix: string) => {
      if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return;
      for (const [key, value] of Object.entries(obj)) {
        const p = `${prefix}.${key}`;
        if (key === command) matches.push(p);
        walk(value, p);
      }
    };
    for (const section of EDITABLE_SECTIONS) {
      if (section === command) matches.push(section);
      walk(this.configManager.getValue(section), section);
    }

    const allowed = matches.filter((p) => !isForbidden(p));
    if (allowed.length === 0) return null;
    if (allowed.length > 1) return allowed;
    // A whole section can be shown but not replaced wholesale.
    return allowed[0];
  }

  // Parses the argument of a set command.
  //  - `"reason text"`  -> string `reason text` (one outer quote pair
  //    stripped - so `""x""` yields the literal string `"x"`, per spec)
  //  - true/false       -> boolean
  //  - 42 / 1.5         -> number
  //  - [..] / {..}      -> parsed JSON
  //  - anything else    -> raw string
  private parseValueArg(arg: string): any {
    if (arg.length >= 2 && arg.startsWith('"') && arg.endsWith('"')) {
      return arg.slice(1, -1);
    }
    if (/^(true|false)$/i.test(arg)) return arg.toLowerCase() === 'true';
    if (/^-?\d+(\.\d+)?$/.test(arg)) return parseFloat(arg);
    if (arg.startsWith('[') || arg.startsWith('{')) {
      try { return JSON.parse(arg); } catch { return undefined; }
    }
    return arg;
  }

  // Returns the expected type name when the new value's type doesn't match
  // the existing one, or null when the assignment is fine.
  private checkType(current: any, next: any): string | null {
    if (current === undefined || current === null) return null;
    if (Array.isArray(current)) return Array.isArray(next) ? null : 'array';
    if (typeof current === 'object') return (typeof next === 'object' && next !== null) ? null : 'object';
    if (typeof current === typeof next) return null;
    return typeof current;
  }

  private formatValue(value: any): string {
    if (value === undefined) return 'undefined';
    if (typeof value === 'string') return value;
    try { return JSON.stringify(value); } catch { return String(value); }
  }
}
