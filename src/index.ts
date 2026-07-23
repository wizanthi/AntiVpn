// src/index.ts - Updated with cache support
import { ConfigManager } from './config/ConfigManager';
import { Logger } from './utils/Logger';
import { CacheService } from './utils/Cache';
import { ListManager } from './services/ListManager';
import { ListUpdater } from './services/ListUpdater';
import { IpChecker } from './services/IpChecker';
import { WebhookService } from './services/WebhookService';
import { SessionManager } from './core/SessionManager';
import { QueueSystem } from './utils/Queue';
import { PlayerTracker } from './core/PlayerTracker';
import { LogCleaner } from './utils/LogCleaner';
import { AppConfig } from './types';
import { NetworkReputationStore } from './services/NetworkReputationStore';
import { IpReputationStore } from './services/IpReputationStore';
import { DatasetLoader } from './services/DatasetLoader';
import { CustomBanManager } from './services/CustomBanManager';
import { StorageAdapter, createStorageAdapter } from './services/StorageAdapter';
import { MlDetector } from './services/MlDetector';
import { RangeIndexStore } from './services/RangeIndexStore';
import { AsnIndex } from './services/AsnIndex';
import { DEFAULT_DATASETS_CONFIG } from './config/DatasetsDefaults';
import * as path from 'path';
import * as fs from 'fs';

const Teeworlds = require('teeworlds');

// Console colors for pretty output
const c = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  cyan: '\x1b[36m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  white: '\x1b[37m',
  dim: '\x1b[2m',
};

// Main bot class
class WizanthiAntiVpn {
  private client: any;
  private configManager: ConfigManager;
  private logger: Logger;
  private sessionManager!: SessionManager;
  private listUpdater!: ListUpdater;
  private logCleaner!: LogCleaner;
  private storageAdapter!: StorageAdapter;
  private config!: AppConfig;
  private isShuttingDown: boolean = false;
  // Resolves once the background list refresh kicked off in
  // initializeServices() finishes - stored so start() can wait on it
  // (alongside IpChecker's dataset/ASN/Tor readiness) before connecting,
  // so the bot joins with every download actually complete instead of
  // racing the first few player checks against still-loading lists.
  private listRefreshPromise!: Promise<void>;

  constructor() {
    this.logger = Logger.getInstance();
    this.configManager = ConfigManager.getInstance();
  }

  private printBanner(): void {
    const mode = this.config.auto_ban?.mode || 'warn';
    const enabled = this.config.auto_ban?.enabled ? 'ON' : 'OFF';
    const hourlyReconnect = this.config.monitoring?.hourly_reconnect ? 'ON' : 'OFF';
    const antivpnOn = this.configManager.isAntiVpnEnabled();
    const modeColor = mode === 'autoban' ? c.red : c.yellow;
    const enabledColor = enabled === 'ON' && mode === 'autoban' ? c.red : c.green;

    console.log('\n');
    console.log(`${c.cyan}${c.bright}╔══════════════════════════════════════════════════╗${c.reset}`);
    console.log(`${c.cyan}${c.bright}║                                                  ║${c.reset}`);
    console.log(`${c.cyan}${c.bright}║     ${c.white}WizanthiAntiVpn v2.0.0${c.cyan}                     ║${c.reset}`);
    console.log(`${c.cyan}${c.bright}║     ${c.dim}DDNet Anti-Abuse Security System${c.cyan}               ║${c.reset}`);
    console.log(`${c.cyan}${c.bright}║                                                  ║${c.reset}`);
    console.log(`${c.cyan}${c.bright}╚══════════════════════════════════════════════════╝${c.reset}`);
    console.log('');
    console.log(`${c.green}  Target: ${c.white}${this.config.server.host}:${this.config.server.port}${c.reset}`);
    console.log(`${c.green}  Bot: ${c.white}${this.config.bot.nickname}${c.reset}`);
    console.log(`${c.green}  Client: ${c.white}DDNet 16.5.0 (whisper-capable)${c.reset}`);
    console.log(`${c.green}  Mode: ${modeColor}${mode.toUpperCase()}${c.reset} ${c.dim}|${c.reset} AutoBan: ${enabledColor}${enabled}${c.reset}`);
    console.log(`${c.green}  AntiVPN: ${antivpnOn ? c.green + 'ENABLED' : c.red + 'DISABLED (paused - "$sudo antivpn enable 1" to resume)'}${c.reset}`);
    console.log(`${c.green}  Hourly Reconnect: ${c.white}${hourlyReconnect}${c.reset}`);
    console.log(`${c.green}  Interval: ${c.white}${this.config.monitoring.status_interval_seconds}s${c.reset}`);
    console.log('');
  }

  private async loadCustomBlacklists(): Promise<void> {
    const listManager = ListManager.getInstance();
    
    const blacklistFiles = [
      path.join(process.cwd(), 'blacklist.txt'),
      path.join(process.cwd(), 'data', 'custom_blacklist.txt'),
      path.join(process.cwd(), 'data', 'manual_blacklist.txt')
    ];
    
    let totalLoaded = 0;
    
    for (const file of blacklistFiles) {
      if (fs.existsSync(file)) {
        console.log(`${c.dim}  Loading: ${file}${c.reset}`);
        const loaded = await listManager.loadCustomBlacklist(file);
        totalLoaded += loaded;
        if (loaded > 0) {
          console.log(`${c.green}    +${loaded} IPs loaded${c.reset}`);
        }
      }
    }
    
    if (totalLoaded > 0) {
      console.log(`${c.green}  Total custom blacklist IPs loaded: ${totalLoaded}${c.reset}`);
    }
  }

  private async initializeServices(): Promise<void> {
    const startupStart = Date.now();
    // 1. Load configuration
    this.config = this.configManager.load();

    this.printBanner();

    // 1b. Stand up the configured storage backend (file/sqlite/mysql - see
    // StorageAdapter.ts) for the small operator-managed stores, and the
    // dedicated bulk range-import store (RangeIndexStore.ts) in parallel -
    // two independent DB connections, no reason to serialize opening them.
    // RangeIndexStore honors the same storage.type choice: if it's 'mysql',
    // lists/datasets/ASN data persist into that MySQL database too (see
    // RangeIndexStore.ts), not just the small operator-managed stores.
    const rangeStore = RangeIndexStore.getInstance();
    CacheService.getInstance().setMaxEntries(this.config.ipcheck?.cache_max_entries || 5000);
    await Promise.all([
      (async () => { this.storageAdapter = await createStorageAdapter(this.config.storage); })(),
      rangeStore.init(this.config.storage),
    ]);
    await Promise.all([
      ListManager.getInstance().initStorage(this.storageAdapter),
      CustomBanManager.getInstance().initStorage(this.storageAdapter),
      IpReputationStore.getInstance().initStorage(this.storageAdapter),
      NetworkReputationStore.getInstance().initStorage(this.storageAdapter),
      CacheService.getInstance().initStorage(this.storageAdapter),
      // ML model + training data ("other" persisted state) also honor the
      // configured backend, so on MySQL nothing is left behind in data/*.json.
      MlDetector.getInstance().initStorage(this.storageAdapter),
    ]);

    // On MySQL, mirror the operator-managed blacklist/whitelist IPs into the
    // same unified blacklist/whitelist tables the bulk list/dataset ranges
    // use (no-op on file/sqlite). Runs after ListManager.initStorage() above
    // so the just-loaded lists are published to the DB immediately.
    ListManager.getInstance().setRangeStore(rangeStore, this.config.storage?.type);

    this.listUpdater = ListUpdater.getInstance();
    await this.listUpdater.init(rangeStore, this.config.storage?.type);

    // 1c. INSTANT LOAD - populate every bulk in-memory index straight from
    // what was already persisted by the last successful import pass. On
    // the SQLite backend (the default) this is a handful of pure bulk DB
    // reads into packed typed arrays - no network, no re-parsing
    // data/datasets or data/lists - and is what lets the bot reach
    // "connecting to server" almost immediately even with a large existing
    // dataset/list corpus, instead of blocking on a full re-download/
    // re-parse cycle every single restart. On the MySQL backend these are
    // real network round trips instead, so "instant" is relative there -
    // still far cheaper than a full re-download/re-parse, just not free.
    console.log('');
    console.log(`${c.cyan}  ⚡ Loading persisted indexes...${c.reset}`);
    await Promise.all([
      ListManager.getInstance().loadStaticRangesFromStore(rangeStore),
      AsnIndex.getInstance().loadFromStore(),
      DatasetLoader.getInstance().loadFromStore(this.config.datasets || DEFAULT_DATASETS_CONFIG),
    ]);

    // 2. Initialize base services
    WebhookService.getInstance(this.config.discord.webhook_url, this.config.discord.alert_webhook_url);

    const cache = CacheService.getInstance();
    if (this.config.ipcheck?.cache_ttl_hours) {
      cache.setTTL(this.config.ipcheck.cache_ttl_hours);
    }

    QueueSystem.getInstance();
    PlayerTracker.getInstance();
    this.logCleaner = LogCleaner.getInstance();
    this.logCleaner.startAutoCleanup();

    // 3. Initialize ListManager
    const listManager = ListManager.getInstance();

    console.log('');
    console.log(`${c.yellow}  ══════════════════════════════════════════════════${c.reset}`);
    console.log(`${c.cyan}  📥 Operator lists loaded${c.reset}`);

    const blStats = listManager.getBlacklistStats();
    const wlStats = listManager.getWhitelistStats();

    console.log(`${c.green}    Blacklist: ${c.white}${blStats.ips} IPs loaded from data/blacklist.json${c.reset}`);
    console.log(`${c.green}    Whitelist: ${c.white}${wlStats.ips} IPs loaded from data/whitelist.json${c.reset}`);

    await this.loadCustomBlacklists();

    // 4. Initialize IpChecker with config - this kicks off DatasetLoader's
    // background reparse (loadAll), AsnIndex's background refresh, and the
    // Tor exit-list refresh, none of which are awaited here.
    const ipChecker = IpChecker.getInstance(this.config);

    const dsStats = DatasetLoader.getInstance().getStats();
    if (dsStats.enabled) {
      console.log(`${c.green}    Datasets (instant): ${c.white}${dsStats.ipv4_ranges} IPv4 ranges, ${dsStats.ipv6_exact + dsStats.ipv6_cidrs} IPv6 entries, ${dsStats.asns} ASNs, ${dsStats.mmdb_databases} MMDBs${c.reset}`);
    } else {
      console.log(`${c.dim}    Datasets disabled (datasets.enabled = false)${c.reset}`);
    }
    console.log(`${c.green}    Startup ready in ${c.white}${Date.now() - startupStart}ms${c.reset} ${c.dim}(background refresh continues after connect)${c.reset}`);

    // 5. Background refresh - deliberately NOT awaited. The bot connects
    // using whatever the instant load above provided; ListUpdater's
    // download pass and DatasetLoader's full reparse each swap in fresh
    // in-memory indexes atomically the moment they finish, with zero
    // connect-path latency either way.
    console.log('');
    console.log(`${c.cyan}  🌐 Refreshing lists from external sources...${c.reset}`);
    this.listRefreshPromise = this.listUpdater.updateAllLists(true)
      .then(() => {
        const stats = this.listUpdater.getStats();
        this.logger.info(`List refresh complete: ${stats.enabled_sources}/${stats.total_sources} sources, ${stats.cached_sources} cached`);
      })
      .catch((e) => this.logger.error('List refresh failed', e));
    this.listUpdater.startAutoUpdate(6);

    // 6. Create Teeworlds client
    this.client = new Teeworlds.Client(
      this.config.server.host,
      this.config.server.port,
      this.config.bot.nickname,
      {
        identity: {
          name: this.config.bot.nickname,
          clan: this.config.bot.clan || 'Security',
          country: -1,
          skin: 'default',
          use_custom_color: 1,
          color_body: 10346103,
          color_feet: 65535
        },
        password: this.config.server.password || undefined,
        // Report a DDNet client version >= VERSION_DDNET_WHISPER (217) so the
        // server delivers /w whispers as real SV_CHAT messages in whisper
        // team-mode (TEAM_WHISPER_RECV = 3) instead of falling back to a
        // plain server-origin line (client_id -1) the message handler can't
        // read. 16050 (DDNet 16.5.0) is the teeworlds library's own tested
        // default: whisper-capable, yet below VERSION_DDNET_ENTITY_NETOBJS
        // (16200) so it doesn't change the snapshot object format the lib
        // parses. Reporting 67 (as before) left whispers unreadable.
        ddnet_version: {
          version: 67000,
          release_version: '67.0'
        },
        NET_VERSION: '0.6 626fce9a778df4d4'
      }
    );
  }

  async start(): Promise<void> {
    console.log(`${c.yellow}  🚀 Starting WizanthiAntiVpn...${c.reset}\n`);
    
    try {
      await this.initializeServices();

      // Join only once every download kicked off above has actually
      // finished - operator lists (ListUpdater), datasets, the ASN index,
      // and the Tor exit list (all three via IpChecker) - instead of
      // connecting on whatever the instant-load step happened to have
      // cached and racing the very first few player checks against
      // still-loading data. The instant-load step already makes the bot
      // fully functional off cached data, so this wait is normally short
      // (just topping up whatever changed since last run); it's only long
      // on a fresh install with no cache yet.
      const waitStart = Date.now();
      console.log(`${c.yellow}  ⏳ Waiting for lists & datasets to finish downloading...${c.reset}`);
      await Promise.all([
        this.listRefreshPromise,
        IpChecker.getInstance().waitForAllReady(),
      ]);
      console.log(`${c.green}  ✅ All data sources ready ${c.dim}(${Date.now() - waitStart}ms)${c.reset}\n`);

      console.log(`${c.green}  🔌 Connecting to server...${c.reset}\n`);
      
      this.sessionManager = new SessionManager(this.client, this.config);
      await this.sessionManager.start();
      
      console.log(`${c.green}  ✅ Bot is running!${c.reset}\n`);
    } catch (error) {
      this.logger.error('Failed to start bot', error);
      console.log(`${c.red}  ❌ Failed to start: ${(error as Error).message}${c.reset}`);
      process.exit(1);
    }
  }

  async stop(): Promise<void> {
    if (this.isShuttingDown) return;
    this.isShuttingDown = true;
    
    console.log(`\n${c.yellow}  🛑 Shutting down...${c.reset}`);
    
    if (this.listUpdater) {
      // Clear the recurring timer AND cancel any refresh that's mid-run -
      // without abort() a Ctrl-C during a ~300-source download would keep
      // the whole pass going (and hold the DB pool open) before the process
      // could exit. abort() makes the download pool stop pulling new work
      // immediately, so shutdown doesn't wait on network round trips.
      this.listUpdater.stopAutoUpdate();
      this.listUpdater.abort();
    }

    if (this.logCleaner) {
      this.logCleaner.stopAutoCleanup();
    }

    DatasetLoader.getInstance().stopAutoReload();
    
    if (this.sessionManager) {
      this.sessionManager.stop();
    }

    // v8.0: flush every store that uses debounced/probabilistic writes
    // during normal operation - a clean shutdown is the one guaranteed
    // point to force a final save. These now run in parallel (they're
    // independent stores/files) and are AWAITED before the storage
    // backend is closed below: previously these were fire-and-forget, so
    // storageAdapter.close() (which actually tears down the sqlite/mysql
    // connection) could run - and on sqlite/mysql, race - while the final
    // write was still in flight, silently dropping the last few
    // minutes of cache/reputation data on every restart.
    await Promise.all([
      CacheService.getInstance().saveToDisk(),
      NetworkReputationStore.getInstance().save(),
      IpReputationStore.getInstance().save(),
    ]);

    // Independent connections - close them in parallel rather than one
    // after another (same reasoning as the Promise.all pairing these two
    // opened with in initializeServices).
    await Promise.all([
      this.storageAdapter ? this.storageAdapter.close() : Promise.resolve(),
      RangeIndexStore.getInstance().close(),
    ]);

    console.log(`${c.green}  ✅ Shutdown complete${c.reset}\n`);
  }
}

// Graceful shutdown handlers
let bot: WizanthiAntiVpn;

const shutdown = async (signal: string) => {
  console.log(`\n${c.yellow}  Received ${signal}, shutting down...${c.reset}`);
  // Watchdog: never let a slow/unreachable storage backend (a MySQL pool
  // that won't drain, a stuck final write, ...) wedge the process open
  // indefinitely. If a clean stop() hasn't finished within the grace window,
  // force-exit anyway. .unref() so this timer never itself keeps the loop
  // alive once stop() completes normally.
  const forceExit = setTimeout(() => {
    console.log(`${c.red}  Shutdown timed out, forcing exit${c.reset}`);
    process.exit(0);
  }, 8000);
  forceExit.unref();
  try {
    if (bot) await bot.stop();
  } catch (e) {
    console.error(`${c.red}  Error during shutdown:${c.reset}`, (e as Error)?.message || e);
  }
  clearTimeout(forceExit);
  process.exit(0);
};

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

process.on('uncaughtException', (error) => {
  console.error(`${c.red}  Uncaught exception:${c.reset}`, error.message);
  console.error(error.stack);
  process.exit(1);
});

process.on('unhandledRejection', (reason: any) => {
  console.error(`${c.red}  Unhandled rejection:${c.reset}`, reason?.message || reason);
  process.exit(1);
});

// Start the bot
(async () => {
  bot = new WizanthiAntiVpn();
  await bot.start();
})();
