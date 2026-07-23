// src/services/CustomBanManager.ts
import { Logger } from '../utils/Logger';
import { RconService, isValidIp } from './RconService';
import { StorageAdapter } from './StorageAdapter';
import { ConfigManager } from '../config/ConfigManager';

interface CustomBan {
  ip: string;
  reason: string;
  duration_minutes: number;
  enabled: boolean;
  banned_at?: string;
}

interface CustomBansData {
  bans: CustomBan[];
  last_updated: string;
}

export class CustomBanManager {
  private static instance: CustomBanManager;
  private logger: Logger;
  private rconService: RconService | null = null;
  private storageAdapter: StorageAdapter | null = null;
  private bans: CustomBan[] = [];
  private bannedCache: Set<string> = new Set();
  private checkInterval: NodeJS.Timeout | null = null;
  // Serialize writes so importBans()'s per-ban saveBans() burst can't fan
  // out into many overlapping writes to the same store - same guard the
  // reputation stores/CacheService already use.
  private isSaving: boolean = false;
  private saveAgainAfter: boolean = false;

  private constructor() {
    this.logger = Logger.getInstance();
  }

  static getInstance(): CustomBanManager {
    if (!CustomBanManager.instance) {
      CustomBanManager.instance = new CustomBanManager();
    }
    return CustomBanManager.instance;
  }

  setRconService(rconService: RconService): void {
    this.rconService = rconService;
  }

  // Load bans via the configured storage backend (file/sqlite/mysql - see
  // StorageAdapter.ts). Called once at bot startup.
  async initStorage(adapter: StorageAdapter): Promise<void> {
    this.storageAdapter = adapter;
    try {
      const data: CustomBansData | null = await adapter.read('custombans');
      if (data) {
        this.bans = data.bans || [];
        this.bannedCache.clear();
        for (const ban of this.bans) {
          if (ban.enabled) {
            this.bannedCache.add(ban.ip);
          }
        }
        this.logger.info(`Loaded ${this.bans.length} custom bans (${this.bannedCache.size} enabled)`);
      } else {
        this.saveBans();
        this.logger.info('Created new custom bans store');
      }
    } catch (error) {
      this.logger.error('Failed to load custom bans', error);
      this.bans = [];
    }
  }

  // Persists via the configured storage backend - same document-per-store
  // model every other store (ListManager/IpReputationStore/
  // NetworkReputationStore/CacheService) uses.
  private saveBans(): void {
    if (!this.storageAdapter) return; // not initialized yet
    if (this.isSaving) {
      // A write is already in flight - coalesce into a single follow-up
      // save instead of starting a second concurrent write.
      this.saveAgainAfter = true;
      return;
    }
    const data: CustomBansData = {
      bans: this.bans,
      last_updated: new Date().toISOString()
    };
    this.isSaving = true;
    this.storageAdapter.write('custombans', data)
      .then(() => this.logger.debug(`Saved ${this.bans.length} custom bans`))
      .catch((error) => this.logger.error('Failed to save custom bans', error))
      .finally(() => {
        this.isSaving = false;
        if (this.saveAgainAfter) {
          this.saveAgainAfter = false;
          this.saveBans();
        }
      });
  }

  isCustomBanned(ip: string): boolean {
    return this.bannedCache.has(ip);
  }

  getBanInfo(ip: string): CustomBan | undefined {
    return this.bans.find(b => b.ip === ip && b.enabled);
  }

  addBan(ip: string, reason: string, durationMinutes: number = 0): void {
    // Reject anything that isn't a syntactically valid IP up front, rather
    // than persisting it and only discovering it's unusable when
    // executeBan() eventually refuses to build a command for it - a bad
    // entry (e.g. from a hand-edited or imported file) is dropped loudly
    // here instead of silently failing every sync cycle from then on.
    if (!isValidIp(ip)) {
      this.logger.warn(`CustomBanManager: refusing to add ban for invalid IP ${JSON.stringify(ip)}`);
      return;
    }
    this.removeBan(ip, false);

    const ban: CustomBan = {
      ip,
      reason,
      duration_minutes: durationMinutes,
      enabled: true,
      banned_at: new Date().toISOString()
    };

    this.bans.push(ban);
    this.bannedCache.add(ip);
    this.saveBans();
    this.logger.info(`Added custom ban: ${ip} (${reason}, ${durationMinutes}min)`);
  }

  removeBan(ip: string, save: boolean = true): void {
    const index = this.bans.findIndex(b => b.ip === ip);
    if (index !== -1) {
      this.bans.splice(index, 1);
      this.bannedCache.delete(ip);
      if (save) this.saveBans();
      this.logger.info(`Removed custom ban: ${ip}`);
    }
  }

  toggleBan(ip: string, enabled: boolean): void {
    const ban = this.bans.find(b => b.ip === ip);
    if (ban) {
      ban.enabled = enabled;
      if (enabled) {
        this.bannedCache.add(ip);
      } else {
        this.bannedCache.delete(ip);
      }
      this.saveBans();
      this.logger.info(`${enabled ? 'Enabled' : 'Disabled'} custom ban: ${ip}`);
    }
  }

  async executeBan(ip: string): Promise<boolean> {
    if (!this.rconService) {
      this.logger.error('RconService not set, cannot execute ban');
      return false;
    }

    const ban = this.getBanInfo(ip);
    if (!ban) {
      this.logger.debug(`No custom ban found for ${ip}`);
      return false;
    }

    try {
      await this.rconService.ban(ban.ip, ban.duration_minutes, ban.reason);
      ban.banned_at = new Date().toISOString();
      this.saveBans();
      this.logger.warn(`Custom banned: ${ban.ip} (${ban.reason}, ${ban.duration_minutes}min)`);
      return true;
    } catch (error) {
      this.logger.error(`Failed to execute custom ban for ${ip}`, error);
      return false;
    }
  }

  async executeAllBans(): Promise<{ total: number; success: number; failed: number }> {
    let success = 0;
    let failed = 0;
    const enabledBans = this.bans.filter(b => b.enabled);

    this.logger.info(`Executing ${enabledBans.length} custom bans...`);

    for (const ban of enabledBans) {
      const result = await this.executeBan(ban.ip);
      if (result) success++;
      else failed++;
      await this.delay(200);
    }

    this.logger.info(`Custom bans executed: ${success} success, ${failed} failed`);
    return { total: enabledBans.length, success, failed };
  }

  async syncBans(): Promise<void> {
    // Master switch off ($sudo antivpn enable 0): the 30-min auto-sync tick
    // keeps running but must not re-apply anything while paused. Checked
    // live so re-enabling takes effect on the next tick without a restart.
    if (!ConfigManager.getInstance().isAntiVpnEnabled()) return;
    const now = Date.now();
    for (const ban of this.bans) {
      if (!ban.enabled) continue;
      // Re-apply a timed ban shortly before it expires on the server so it
      // stays in effect, using its ACTUAL duration - the old hardcoded 1h
      // constant re-applied a 2h ban needlessly at 1h and only refreshed a
      // 30min ban an hour after it had already lapsed.
      const expired = ban.duration_minutes > 0 &&
        (now - new Date(ban.banned_at as string).getTime()) > ban.duration_minutes * 60000;
      if (!ban.banned_at || expired) {
        await this.executeBan(ban.ip);
        await this.delay(100);
      }
    }
  }

  startAutoSync(intervalMinutes: number = 30): void {
    if (this.checkInterval) return;
    this.checkInterval = setInterval(async () => {
      await this.syncBans();
    }, intervalMinutes * 60 * 1000);
    this.logger.info(`Custom bans auto-sync started (every ${intervalMinutes}min)`);
  }

  stopAutoSync(): void {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
      this.checkInterval = null;
    }
  }

  importBans(bans: Array<{ ip: string; reason: string; duration_minutes?: number }>): number {
    let added = 0;
    for (const ban of bans) {
      if (!this.isCustomBanned(ban.ip)) {
        this.addBan(ban.ip, ban.reason, ban.duration_minutes || 0);
        added++;
      }
    }
    return added;
  }

  exportBans(): CustomBan[] {
    return [...this.bans];
  }

  getStats(): { total: number; enabled: number; disabled: number } {
    return {
      total: this.bans.length,
      enabled: this.bans.filter(b => b.enabled).length,
      disabled: this.bans.filter(b => !b.enabled).length
    };
  }

  async reload(): Promise<void> {
    if (!this.storageAdapter) return;
    await this.initStorage(this.storageAdapter);
    this.logger.info('Custom bans reloaded from storage');
  }

  private delay(ms: number): Promise<void> {
    return new Promise(r => setTimeout(r, ms));
  }
}