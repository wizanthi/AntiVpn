// src/core/SessionManager.ts - FIXED
import { Logger } from '../utils/Logger';
import { RconService } from '../services/RconService';
import { WebhookService } from '../services/WebhookService';
import { PlayerTracker } from './PlayerTracker';
import { ListManager } from '../services/ListManager';
import { CacheService } from '../utils/Cache';
import { LogCleaner } from '../utils/LogCleaner';
import { CustomBanManager } from '../services/CustomBanManager';
import { AdminCommandService } from '../services/AdminCommandService';
import { ConfigManager } from '../config/ConfigManager';
import { AppConfig, StatusPlayer } from '../types';

export class SessionManager {
  private client: any;
  private config: AppConfig;
  private logger: Logger;
  private rconService: RconService;
  private webhookService: WebhookService;
  private playerTracker: PlayerTracker;
  private listManager: ListManager;
  private cache: CacheService;
  private logCleaner: LogCleaner;
  private customBanManager: CustomBanManager;
  private adminCommands: AdminCommandService;
  private configManager: ConfigManager;
  private isRunning: boolean = false;
  private reconnectAttempts: number = 0;
  private statusInterval: NodeJS.Timeout | null = null;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private hourlyReconnectTimer: NodeJS.Timeout | null = null;
  private playerIpHistory: Map<number, string> = new Map();
  private joinListenerActive: boolean = false;
  // Guards against overlapping status scans. The initial scan is kicked off
  // in the background (see onConnected) and can still be running when the
  // 30s interval fires its first tick; without this guard the two would
  // process the same not-yet-cached players concurrently and each fan out a
  // duplicate external lookup + webhook.
  private scanInProgress: boolean = false;
  // Set right before the scheduled hourly reconnect calls Disconnect(), so
  // the disconnect handler knows this drop was deliberate and must NOT
  // schedule its own reconnect (the hourly handler reconnects itself) -
  // without this the two race and open two concurrent connections.
  private intentionalReconnect: boolean = false;
  // Set by stop() (graceful shutdown). Once true, no disconnect ever
  // schedules a reconnect - otherwise the Disconnect() stop() itself issues
  // would immediately trigger the reconnect path and fight the shutdown.
  private stopped: boolean = false;

  constructor(client: any, config: AppConfig) {
    this.client = client;
    this.config = config;
    this.logger = Logger.getInstance();
    this.rconService = new RconService(client);
    this.webhookService = WebhookService.getInstance();
    this.playerTracker = PlayerTracker.getInstance();
    this.listManager = ListManager.getInstance();
    this.cache = CacheService.getInstance();
    this.logCleaner = LogCleaner.getInstance();
    this.customBanManager = CustomBanManager.getInstance();
    this.configManager = ConfigManager.getInstance();
    // In-game `$sudo antivpn ...` commands, gated on the join-IP the session
    // already remembers for every client (playerIpHistory).
    this.adminCommands = new AdminCommandService(
      config,
      this.rconService,
      (clientId: number) => this.playerIpHistory.get(clientId)
    );

    this.setupEventListeners();
  }

  private setupEventListeners(): void {
    this.client.on('connected', () => this.onConnected());
    this.client.on('disconnect', (reason: string, fromServer: boolean) => this.onDisconnect(reason, fromServer));
    // Chat + whispers. DDNet delivers a /w addressed to us as SV_CHAT with
    // team >= 2 (TEAM_WHISPER_RECV/SEND); public and team chat use 0/1.
    // client_id -1 is the server itself - never a command source.
    this.client.on('message', (msg: { team: number; client_id: number; message: string }) => {
      if (!this.joinListenerActive) return;
      if (typeof msg?.client_id !== 'number' || msg.client_id < 0) return;
      const isWhisper = msg.team >= 2;
      this.adminCommands.handleChatMessage(msg.client_id, msg.message || '', isWhisper);
    });
  }

  private async onConnected(): Promise<void> {
    this.reconnectAttempts = 0;
    // A reconnect succeeded - cancel any still-pending reconnect timer so a
    // stale one can't fire connect() again while we're already connected.
    if (this.reconnectTimer) { clearTimeout(this.reconnectTimer); this.reconnectTimer = null; }
    this.isRunning = true;
    this.intentionalReconnect = false;
    this.playerIpHistory.clear();
    this.joinListenerActive = false;
    
    try {
      this.client.game.SetTeam(-1);
      
      await this.rconService.login(this.config.server.rcon_password, this.config.server.rcon_username);
      
      this.playerTracker.setRconService(this.rconService);
      this.customBanManager.setRconService(this.rconService);

      await this.rconService.execute('hide_auth_status 1');
      await this.rconService.execute('show_ips 1');

      // Master switch off ($sudo antivpn enable 0): don't re-apply the
      // stored custom bans on (re)connect - "disabled" must mean no bans of
      // any kind. Read live so an in-session toggle affects the very next
      // hourly reconnect.
      if (this.configManager.isAntiVpnEnabled()) {
        await this.customBanManager.executeAllBans();
      } else {
        this.logger.warn('AntiVPN is DISABLED (antivpn.enabled=0) - monitoring paused, use "$sudo antivpn enable 1" to resume');
      }

      // Arm monitoring and declare the session ready IMMEDIATELY. Everything
      // below this point (the startup webhook and the first full scan of
      // whoever is already online) is deliberately NOT awaited: when the bot
      // connects to a populated server, that initial scan runs a per-player
      // external IP-intelligence lookup AND a Discord webhook for every
      // not-yet-cached player online. Awaiting it here used to delay "Session
      // ready" - and the very first 30s monitor tick - by minutes on a full
      // server. The join listener, interval, and ban sync are all live before
      // the scan starts, so nothing is missed while it runs in the background.
      this.setupJoinListener();
      this.joinListenerActive = true;

      this.statusInterval = setInterval(() => this.checkStatus(), 30000);

      this.customBanManager.startAutoSync(30);

      if (this.config.monitoring.hourly_reconnect) {
        this.setupHourlyReconnect();
      }

      this.logger.info('Session ready - checking every 30s');

      // Fire-and-forget: a slow/unreachable Discord endpoint must never hold
      // up session start (axios already caps each attempt, but 429 back-off
      // can still stack seconds).
      const ws = this.listManager.getWhitelistStats();
      const bs = this.listManager.getBlacklistStats();
      this.webhookService.sendStartupMessage({
        server: `${this.config.server.host}:${this.config.server.port}`,
        whitelist: ws.ips,
        blacklist: bs.ips
      }).catch((e) => this.logger.error('Startup webhook failed', e));

      // Background the initial scan of already-online players - the 30s
      // interval and the scan share the scanInProgress guard so they can't
      // double-process the same players.
      void this.runStatusScan(true);
    } catch (error) {
      this.logger.error('Connection initialization failed', error);
    }
  }

  private setupHourlyReconnect(): void {
    // Clear any prior timer first - onConnected() runs on every (re)connect,
    // so without this each reconnect would stack another live hourly timer
    // that never gets cleared, compounding into a reconnect storm.
    if (this.hourlyReconnectTimer) { clearInterval(this.hourlyReconnectTimer); this.hourlyReconnectTimer = null; }

    const intervalMinutes = this.config.monitoring.reconnect_interval_minutes || 60;
    const intervalMs = intervalMinutes * 60 * 1000;

    this.logger.info(`Hourly reconnect scheduled every ${intervalMinutes} minutes`);

    this.hourlyReconnectTimer = setInterval(async () => {
      this.logger.info('Performing scheduled reconnect...');
      this.cache.saveToDisk();

      // Flag this as a deliberate drop so onDisconnect() doesn't ALSO fire
      // its own reconnect - this handler owns the reconnect below.
      this.intentionalReconnect = true;
      try { if (this.client) { this.client.Disconnect(); } } catch (e) {}

      await this.delay(3000);

      try {
        await this.client.connect();
        this.logger.info('Scheduled reconnect successful');
      } catch (error) {
        this.logger.error('Scheduled reconnect failed', error);
        // The scheduled connect() rejected and won't emit a 'disconnect'
        // event to drive recovery, so hand off to the normal retry-forever
        // path here instead of leaving the bot offline until manual restart.
        this.intentionalReconnect = false;
        this.scheduleReconnect();
      }
    }, intervalMs);
  }

  private async onDisconnect(reason: string, fromServer: boolean): Promise<void> {
    this.isRunning = false;
    this.joinListenerActive = false;

    if (this.statusInterval) { clearInterval(this.statusInterval); this.statusInterval = null; }
    // Stop the hourly reconnect timer on every disconnect (onConnected
    // re-arms it) so it can't accumulate across reconnects.
    if (this.hourlyReconnectTimer) { clearInterval(this.hourlyReconnectTimer); this.hourlyReconnectTimer = null; }

    this.playerIpHistory.clear();

    // A deliberate hourly-reconnect drop reconnects itself - don't also
    // schedule a second, racing reconnect here.
    if (this.intentionalReconnect) {
      this.intentionalReconnect = false;
      return;
    }

    // Graceful shutdown in progress (stop() called Disconnect()) - staying
    // down is the whole point, so never reconnect here.
    if (this.stopped) return;

    this.logger.warn(`Disconnected${fromServer ? ' by server' : ''}${reason ? `: ${reason}` : ''} - will keep trying to reconnect`);
    this.scheduleReconnect();
  }

  // Schedules the next reconnect attempt. The server going down (restart,
  // crash, maintenance) is exactly when the bot must keep trying rather than
  // give up, so this retries FOREVER with capped exponential backoff instead
  // of stopping after max_reconnect_attempts - past that cap it simply keeps
  // retrying at the ceiling delay. max_reconnect_attempts is still honored as
  // the point where the backoff stops growing and the log switches to a
  // "still down, retrying" warning. connect() itself rejecting (server still
  // unreachable) does NOT reliably emit a 'disconnect' event, so this path
  // re-arms itself on failure rather than trusting the disconnect handler to
  // fire again - without that, a single failed reconnect would silently end
  // the whole retry chain and leave the bot offline until a manual restart.
  private scheduleReconnect(): void {
    if (this.stopped) return; // graceful shutdown - don't reconnect
    if (this.reconnectTimer) { clearTimeout(this.reconnectTimer); this.reconnectTimer = null; }

    this.reconnectAttempts++;
    const base = this.config.monitoring.reconnect_delay_ms || 3000;
    // Cap the exponent as well as the result: without it the 1.5^attempts
    // term overflows to Infinity after ~1800 attempts of a long outage.
    const grownDelay = base * Math.pow(1.5, Math.min(this.reconnectAttempts, 20));
    const delay = Math.min(grownDelay, 30000);
    const max = this.config.monitoring.max_reconnect_attempts;

    if (max > 0 && this.reconnectAttempts > max) {
      this.logger.warn(`Still disconnected after ${this.reconnectAttempts} attempts - retrying every ${Math.round(delay / 1000)}s until the server returns`);
    } else {
      this.logger.info(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts}${max > 0 ? `/${max}` : ''})`);
    }

    this.reconnectTimer = setTimeout(() => {
      if (this.stopped) return;
      this.client.connect().catch((err: any) => {
        // Socket-level connect failed and no 'disconnect' event will follow
        // to drive the next attempt - re-arm here so the retry chain can't
        // silently die while the server is still down.
        this.logger.warn('Reconnect attempt failed', err?.message || err);
        this.scheduleReconnect();
      });
    }, delay);
  }

  // Single status-scan path shared by the backgrounded initial scan (kicked
  // off from onConnected) and the recurring 30s tick. scanInProgress ensures
  // only one runs at a time: the initial scan on a busy server can outlast
  // the first interval tick, and processing the same players twice would
  // duplicate every external lookup + webhook.
  private async runStatusScan(initial: boolean): Promise<void> {
    if (this.scanInProgress) return;
    if (!initial && !this.isRunning) return;
    this.scanInProgress = true;
    try {
      const status = await this.rconService.executeStatus();
      if (status.players.length > 0) {
        if (initial) this.logger.info(`Found ${status.players.length} players on server`);
        // Always record join IPs, even with the master switch off - admin
        // command auth (AdminCommandService.resolveIp) depends on this map,
        // and it's what lets a whitelisted admin still run
        // `$sudo antivpn enable 1` while everything else is paused.
        for (const p of status.players) { this.playerIpHistory.set(p.id, p.ip); }
        // Master switch off: still check/track everyone via the normal
        // scan path (bans stay gated inside PlayerTracker/CustomBanManager
        // themselves) so status keeps reflecting reality and re-enabling
        // has an up-to-date picture to sweep.
        await this.playerTracker.processStatus(status.players);
      }
    } catch (error) {
      this.logger.warn(initial ? 'Initial status check failed' : 'Status check failed', error);
    } finally {
      this.scanInProgress = false;
    }
  }

  private async checkStatus(): Promise<void> {
    if (!this.isRunning) return;
    await this.runStatusScan(false);
  }

  private setupJoinListener(): void {
    this.rconService.onPlayerJoin((player: StatusPlayer) => {
      if (!this.joinListenerActive) return;
      if (player.nickname === this.config.bot.nickname) return;
      
      const prevIp = this.playerIpHistory.get(player.id);
      this.playerIpHistory.set(player.id, player.ip);

      if (prevIp === player.ip) {
        // Same connection announced again - this is the batched name
        // resolver delivering the real nickname after the immediate
        // join-line callback already started the IP check. Patch the name
        // into tracking, but never start a second check.
        this.playerTracker.updatePlayerName(player.id, player.nickname, player.clan);
        return;
      }
      if (this.listManager.isPrivateIP(player.ip)) return;

      // Master switch off ($sudo antivpn enable 0): still check and track
      // every join in real time - so operators can see what's connecting and
      // banAllPendingSuspicious() has something to act on the instant the
      // switch flips back on - but never ban or clean anything while paused.
      // The actual ban/custom-ban EXECUTION is gated inside
      // PlayerTracker/CustomBanManager themselves (isAntiVpnEnabled()), not
      // here, so disabled truly means "check-only" end to end.

      // Bounded-concurrency enqueue rather than a direct checkIpForPlayer:
      // during a bot swarm many joins arrive in the same instant, and firing
      // an unbounded IP check per join overruns the external APIs' rate limits
      // (each check fans out to ~15 of them), making checks fail and fall
      // through to the fail-open "trusted" path. The queue caps in-flight
      // checks at max_parallel_checks so every joiner in the burst is really
      // checked. See PlayerTracker.enqueueJoinCheck.
      this.playerTracker.enqueueJoinCheck(player);
    });

    this.rconService.onPlayerLeave((clientId: number) => {
      if (!this.joinListenerActive) return;
      this.playerTracker.checkPlayerOnLeave(clientId);
      // Server client IDs can be reused. Clear the departed connection so a
      // return with the same ID/IP is a genuine rejoin, not a duplicate name
      // resolution callback. This makes custom bans execute on every rejoin.
      this.playerIpHistory.delete(clientId);
    });
  }

  async start(): Promise<void> { await this.client.connect(); }

  stop(): void {
    this.stopped = true;
    this.isRunning = false;
    this.joinListenerActive = false;
    if (this.statusInterval) { clearInterval(this.statusInterval); this.statusInterval = null; }
    if (this.reconnectTimer) { clearTimeout(this.reconnectTimer); this.reconnectTimer = null; }
    if (this.hourlyReconnectTimer) { clearInterval(this.hourlyReconnectTimer); this.hourlyReconnectTimer = null; }
    this.customBanManager.stopAutoSync();
    this.playerTracker.clear();
    this.playerIpHistory.clear();
    try { if (this.client) { this.client.Disconnect(); } } catch (e) {}
  }

  private delay(ms: number): Promise<void> { return new Promise(resolve => setTimeout(resolve, ms)); }
}