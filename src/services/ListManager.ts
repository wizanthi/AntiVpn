// src/services/ListManager.ts - UPDATED with blacklist.json loading
import * as fs from 'fs';
import { WhitelistData, BlacklistData, BlacklistEntry, WhitelistEntry } from '../types';
import { Logger } from '../utils/Logger';
import { StorageAdapter } from './StorageAdapter';
import { RangeTable } from './RangeTable';
import { RangeIndexStore } from './RangeIndexStore';

// List manager - handles whitelist and blacklist operations - singleton pattern
export class ListManager {
  private static instance: ListManager;
  private whitelist: WhitelistData;
  private blacklist: BlacklistData;
  private storageAdapter: StorageAdapter | null = null;
  private logger: Logger;
  private blacklistSet: Set<string> = new Set();
  private blacklistCidrs: string[] = [];
  // Mirror of blacklistCidrs for O(1) membership tests during bulk import -
  // addManyToBlacklist used to dedup CIDRs with a linear Array.includes(),
  // making a large custom-CIDR import O(n²). Kept in sync at every site that
  // mutates blacklistCidrs.
  private blacklistCidrSet: Set<string> = new Set();
  // Indexed the same way as the blacklist below: isWhitelisted() runs on
  // every single connection (Layer 0, before any network call), so it
  // needs to be O(1)/O(small) rather than the two full-array .includes()
  // scans this used to do - each one is O(n) over every whitelisted IP,
  // every time any player connects.
  private whitelistSet: Set<string> = new Set();
  private whitelistCidrs: string[] = [];
  // Same overlapping-write guard as CacheService: addToBlacklist/
  // addToWhitelist can each fire multiple times in quick succession (e.g.
  // several players banned back-to-back), and these saves are now async
  // fire-and-forget rather than blocking writeFileSync calls.
  private isSavingWhitelist: boolean = false;
  private saveWhitelistAgain: boolean = false;
  private isSavingBlacklist: boolean = false;
  private saveBlacklistAgain: boolean = false;

  // Optional mirror of the operator-managed blacklist/whitelist IPs into the
  // unified MySQL blacklist/whitelist tables (see RangeIndexStore). Only
  // active when storage.type = 'mysql' - on file/sqlite these lists already
  // persist as JSON documents via the StorageAdapter and the range-store
  // mirror methods are no-ops. Set once at startup via setRangeStore().
  private rangeStore: RangeIndexStore | null = null;
  private mirrorToDb: boolean = false;

  // --- Static curated-list index (bulk data from ListUpdater) ---
  //
  // Curated sources (X4BNet, FireHOL, per-ASN prefix lists, etc.) can total
  // millions of entries. Storing those in the same growing blacklist.json
  // array and doing a linear scan per connection - and rewriting the whole
  // file to disk on every write - does not scale to a live game server:
  // a single player connecting would trigger an O(n) scan across millions
  // of CIDRs, and every new dynamic ban would re-serialize the entire file.
  //
  // So curated bulk data lives ONLY in memory here, backed by
  // RangeIndexStore (see that file) as the persistent source of truth -
  // never through the small, frequently-rewritten blacklist.json. Every
  // entry (bare IP or CIDR) is stored as a numeric [start,end] range (a
  // bare IP is a degenerate single-address range) and held as a packed
  // typed-array RangeTable for O(log n) binary search with none of the
  // per-entry boxed-array/object overhead a plain JS array would carry.
  private staticRangeTable: RangeTable = RangeTable.EMPTY;

  // Permanent whitelist - always trusted
  private permanentWhitelist: string[] = ['127.0.0.1', 'localhost', '::1'];

  private constructor() {
    this.logger = Logger.getInstance();
    this.whitelist = { ips: [], players: [], providers: [], auto_added: [] };
    this.blacklist = { ips: [], players: [], auto_added: [] };
  }

  static getInstance(): ListManager {
    if (!ListManager.instance) ListManager.instance = new ListManager();
    return ListManager.instance;
  }

  // Load lists via the configured storage backend (file/sqlite/mysql - see
  // StorageAdapter.ts). Called once at bot startup, before anything reads
  // getBlacklistStats()/isWhitelisted()/etc.
  async initStorage(adapter: StorageAdapter): Promise<void> {
    this.storageAdapter = adapter;

    try {
      const wl = await adapter.read('whitelist');
      if (wl) {
        this.whitelist = wl;
        if (!this.whitelist.providers) this.whitelist.providers = [];
        if (!this.whitelist.auto_added) this.whitelist.auto_added = [];
        this.logger.info(`Loaded whitelist: ${this.whitelist.ips.length} IPs`);
      } else {
        this.saveWhitelist();
      }
    } catch (e) {
      this.whitelist = { ips: [], players: [], providers: [], auto_added: [] };
      this.logger.warn('Failed to load whitelist, using empty');
    }

    try {
      const bl = await adapter.read('blacklist');
      if (bl) {
        this.blacklist = bl;
        if (!this.blacklist.auto_added) this.blacklist.auto_added = [];
        this.logger.info(`Loaded blacklist: ${this.blacklist.ips.length} IPs`);
      } else {
        this.saveBlacklist();
      }
    } catch (e) {
      this.blacklist = { ips: [], players: [], auto_added: [] };
      this.logger.warn('Failed to load blacklist, using empty');
    }

    this.rebuildBlacklistIndex();
    this.rebuildWhitelistIndex();
  }

  // Wire up the bulk range store so operator blacklist/whitelist IPs are
  // mirrored into the unified MySQL blacklist/whitelist tables alongside the
  // curated list and dataset ranges. Called once from index.ts's startup,
  // after initStorage() has already loaded the current lists. MySQL-only:
  // on file/sqlite the range-store mirror methods are deliberate no-ops, so
  // mirrorToDb stays false and nothing extra is written. The initial mirror
  // below publishes whatever was just loaded so the DB tables reflect the
  // operator lists immediately, not only after the next add/remove.
  setRangeStore(store: RangeIndexStore, storageType?: string): void {
    this.rangeStore = store;
    this.mirrorToDb = storageType === 'mysql';
    if (this.mirrorToDb) {
      this.mirrorBlacklistToDb();
      this.mirrorWhitelistToDb();
    }
  }

  // Full replace of the kind='operator' rows in the MySQL blacklist/whitelist
  // tables from the current in-memory lists. Fire-and-forget: a DB hiccup
  // must never block or crash the (already-persisted-elsewhere) list save.
  // Operator lists are small (thousands at most), so a wholesale replace per
  // debounced save is cheap. IPv6 entries are skipped - the numeric range
  // tables are IPv4-only, same stance as the rest of this file.
  private mirrorBlacklistToDb(): void {
    if (!this.mirrorToDb || !this.rangeStore) return;
    const ranges = this.entriesToRanges(this.blacklist.ips);
    this.rangeStore.replaceOperatorBlacklist(ranges)
      .catch((e) => this.logger.warn('Failed to mirror operator blacklist to DB', e));
  }

  private mirrorWhitelistToDb(): void {
    if (!this.mirrorToDb || !this.rangeStore) return;
    const ranges = this.entriesToRanges(this.whitelist.ips);
    this.rangeStore.replaceOperatorWhitelist(ranges)
      .catch((e) => this.logger.warn('Failed to mirror operator whitelist to DB', e));
  }

  // Convert operator IP/CIDR strings into numeric [start,end] ranges for the
  // packed blacklist/whitelist tables, masking host bits off misaligned
  // CIDRs (same reasoning as ListUpdater.entryToRange) and dropping IPv6.
  private entriesToRanges(ips: string[]): Array<[number, number]> {
    const ranges: Array<[number, number]> = [];
    for (const ip of ips) {
      if (ip.includes(':')) continue; // IPv4-only range table
      if (ip.includes('/')) {
        const [range, bitsStr] = ip.split('/');
        const bits = parseInt(bitsStr, 10);
        if (isNaN(bits) || bits < 0 || bits > 32) continue;
        if (range.includes(':')) continue;
        const base = this.ipToNumber(range);
        const mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
        const start = (base & mask) >>> 0;
        const size = bits === 0 ? 0x100000000 : Math.pow(2, 32 - bits);
        const end = (start + size - 1) >>> 0;
        ranges.push([start, end]);
      } else {
        const parts = ip.split('.');
        if (parts.length !== 4) continue; // not a parseable IPv4 literal
        const num = this.ipToNumber(ip);
        ranges.push([num, num]);
      }
    }
    return ranges;
  }

  private rebuildWhitelistIndex(): void {
    this.whitelistSet.clear();
    this.whitelistCidrs = [];
    for (const ip of this.whitelist.ips) {
      if (ip.includes('/')) this.whitelistCidrs.push(ip);
      else this.whitelistSet.add(ip);
    }
    this.logger.debug(`Whitelist index rebuilt: ${this.whitelistSet.size} IPs, ${this.whitelistCidrs.length} CIDRs`);
  }

  private rebuildBlacklistIndex(): void {
    this.blacklistSet.clear();
    this.blacklistCidrs = [];
    this.blacklistCidrSet.clear();
    for (const ip of this.blacklist.ips) {
      if (ip.includes('/')) { this.blacklistCidrs.push(ip); this.blacklistCidrSet.add(ip); }
      else this.blacklistSet.add(ip);
    }
    this.logger.debug(`Blacklist index rebuilt: ${this.blacklistSet.size} IPs, ${this.blacklistCidrs.length} CIDRs`);
  }

  // Check if IP is whitelisted
  isWhitelisted(ip: string): boolean {
    if (this.permanentWhitelist.includes(ip)) return true;
    if (this.whitelistSet.has(ip)) return true;
    for (const cidr of this.whitelistCidrs) {
      if (this.ipInCIDR(ip, cidr)) return true;
    }
    return false;
  }

  // Check if provider is whitelisted by name
  isWhitelistedByProvider(isp: string, org: string): boolean {
    const ispLower = (isp || '').toLowerCase().trim();
    const orgLower = (org || '').toLowerCase().trim();
    const providers = this.whitelist.providers || [];
    
    for (const provider of providers) {
      const pLower = provider.toLowerCase();
      if (ispLower.includes(pLower) || orgLower.includes(pLower)) {
        return true;
      }
    }
    return false;
  }

  // Add IP to whitelist
  addToWhitelist(ip: string, reason: string = 'Auto-added'): void {
    if (this.isWhitelisted(ip)) return;
    this.whitelist.ips.push(ip);
    if (ip.includes('/')) this.whitelistCidrs.push(ip);
    else this.whitelistSet.add(ip);
    this.whitelist.auto_added.push({ ip, reason, added_at: new Date().toISOString() });
    this.saveWhitelist();
  }

  // Check if IP is blacklisted (dynamic detections + curated static index)
  isBlacklisted(ip: string): boolean {
    if (this.blacklistSet.has(ip)) return true;
    for (const cidr of this.blacklistCidrs) {
      if (this.ipInCIDR(ip, cidr)) return true;
    }
    if (!ip.includes(':')) {
      if (this.staticRangeTable.has(this.ipToNumber(ip))) return true;
    }
    return false;
  }

  // Loads the curated-list union straight from RangeIndexStore into a
  // packed RangeTable - near-instant (one bulk ordered SELECT, no network,
  // no re-parsing raw list files), so this can run at startup before
  // ListUpdater's background refresh has done anything. Called again every
  // time ListUpdater finishes a refresh cycle to atomically swap in the
  // latest data. Never touches blacklist.json.
  async loadStaticRangesFromStore(store: RangeIndexStore): Promise<void> {
    const { starts, ends } = await store.loadListRangesUnion();
    this.staticRangeTable = RangeTable.fromSortedPairs(starts, ends);
    this.logger.info(`Static curated-list index (re)loaded: ${this.staticRangeTable.size} merged ranges`);
  }

  getStaticListStats() {
    return { merged_ranges: this.staticRangeTable.size };
  }

  // Add IP to blacklist
  addToBlacklist(ip: string, reason: string = 'VPN/Proxy', method: string = 'Auto'): void {
    if (this.isBlacklisted(ip)) return;
    // Remove from whitelist if present
    if (this.isWhitelisted(ip)) {
      this.whitelist.ips = this.whitelist.ips.filter((i: string) => i !== ip);
      this.whitelistSet.delete(ip);
      this.whitelistCidrs = this.whitelistCidrs.filter((c: string) => c !== ip);
      this.saveWhitelist();
    }
    if (ip.includes('/')) { this.blacklistCidrs.push(ip); this.blacklistCidrSet.add(ip); }
    else this.blacklistSet.add(ip);
    this.blacklist.ips.push(ip);
    this.blacklist.auto_added.push({ ip, reason, added_at: new Date().toISOString(), detection_method: method });
    this.saveBlacklist();
    this.logger.warn(`Blacklisted: ${ip} - ${reason}`);
  }

  // Remove a single dynamically-added IP/CIDR from the blacklist - used by
  // the quarantine re-verification worker when a formerly-banned IP's full
  // re-check comes back clean. Never touches the curated static range index
  // (staticRangeTable) - that's ListUpdater's data, not a dynamic ban.
  removeFromBlacklist(ip: string): boolean {
    let removed = false;
    if (this.blacklistSet.delete(ip)) removed = true;
    if (this.blacklistCidrSet.has(ip)) {
      this.blacklistCidrSet.delete(ip);
      this.blacklistCidrs = this.blacklistCidrs.filter((c: string) => c !== ip);
      removed = true;
    }
    if (removed) {
      this.blacklist.ips = this.blacklist.ips.filter((i: string) => i !== ip);
      this.blacklist.auto_added = this.blacklist.auto_added.filter((e: BlacklistEntry) => e.ip !== ip);
      this.saveBlacklist();
    }
    return removed;
  }

  // FP-hardening (dataset provenance): removes dynamically-added blacklist
  // entries whose detection_method matches `method` but that `stillValid`
  // no longer vouches for. Called after every dataset (re)load so deleting
  // a bad dataset file actually un-blacklists its victims instead of
  // leaving those bans permanent forever. One disk write for the batch.
  // Detection unchanged: entries the datasets still list are kept as-is,
  // and pruned IPs go through the FULL check pipeline on next connection.
  pruneBlacklistByMethod(method: string, stillValid: (ip: string) => boolean): string[] {
    const pruned: string[] = [];
    for (const entry of this.blacklist.auto_added) {
      if (entry.detection_method !== method) continue;
      const ip = entry.ip;
      if (!ip || ip.startsWith('batch:')) continue; // batch markers aren't real IPs
      if (stillValid(ip)) continue;
      pruned.push(ip);
    }
    if (pruned.length === 0) return pruned;
    const prunedSet = new Set(pruned);
    for (const ip of pruned) {
      this.blacklistSet.delete(ip);
      if (this.blacklistCidrSet.has(ip)) {
        this.blacklistCidrSet.delete(ip);
        this.blacklistCidrs = this.blacklistCidrs.filter((c: string) => c !== ip);
      }
    }
    this.blacklist.ips = this.blacklist.ips.filter((i: string) => !prunedSet.has(i));
    this.blacklist.auto_added = this.blacklist.auto_added.filter(
      (e: BlacklistEntry) => !(e.detection_method === method && prunedSet.has(e.ip))
    );
    this.saveBlacklist();
    this.logger.info(`Blacklist: pruned ${pruned.length} stale ${method}-sourced entries no longer backed by their source`);
    return pruned;
  }

  // Batch-add IPs to blacklist (single disk write)
  addManyToBlacklist(ips: string[], reason: string, method: string = 'Auto-Import'): number {
    let added = 0;

    for (const ip of ips) {
      if (this.isWhitelisted(ip) || this.isPrivateIP(ip)) continue;
      if (ip.includes('/')) {
        if (this.blacklistCidrSet.has(ip)) continue;
        this.blacklistCidrs.push(ip);
        this.blacklistCidrSet.add(ip);
      } else {
        if (this.blacklistSet.has(ip)) continue;
        this.blacklistSet.add(ip);
      }
      this.blacklist.ips.push(ip);
      added++;
    }

    if (added > 0) {
      this.blacklist.auto_added.push({
        ip: `batch:${added}`,
        reason,
        added_at: new Date().toISOString(),
        detection_method: method
      });
      this.saveBlacklist();
      this.logger.info(`Imported ${added} IPs (${reason})`);
    }

    return added;
  }

  // Get IP status
  getIpStatus(ip: string): 'permanent_whitelist' | 'whitelisted' | 'blacklisted' | 'needs_check' {
    if (this.permanentWhitelist.includes(ip)) return 'permanent_whitelist';
    if (this.isWhitelisted(ip)) return 'whitelisted';
    if (this.isBlacklisted(ip)) return 'blacklisted';
    return 'needs_check';
  }

  // Check if IP is in CIDR range
  private ipInCIDR(ip: string, cidr: string): boolean {
    // This math is IPv4-only (ipToNumber below). Without this guard, an
    // IPv6 address on either side collapses through ipToNumber's "return 0
    // for IPv6" shortcut - both ipNum and rangeNum become 0, the mask
    // comparison (0 & mask) === (0 & mask) is trivially true, and *every*
    // IPv6 address would match *any* IPv6 CIDR entry ever added to the
    // whitelist or blacklist (a universal bypass, or a universal false-
    // positive ban, for the entire IPv6 address space). Bail out instead -
    // consistent with loadStaticList's existing "IPv6 CIDRs skipped, this
    // project's IP handling is IPv4-focused" stance elsewhere in this file.
    if (ip.includes(':') || cidr.includes(':')) return false;
    const [range, bits] = cidr.split('/');
    const mask = ~(2 ** (32 - parseInt(bits)) - 1);
    const ipNum = this.ipToNumber(ip);
    const rangeNum = this.ipToNumber(range);
    return (ipNum & mask) === (rangeNum & mask);
  }

  // Convert IP to number for CIDR calculations
  private ipToNumber(ip: string): number {
    if (ip.includes(':')) return 0; // Skip IPv6
    return ip.split('.').reduce((acc, o) => (acc << 8) + parseInt(o), 0) >>> 0;
  }

  // Check if IP is private/local
  isPrivateIP(ip: string): boolean {
    if (ip === '::1' || ip === 'localhost') return true;
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4) return false;
    if (parts[0] === 10) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 127) return true;
    return false;
  }

  // Save whitelist via the configured storage backend. Same overlapping-
  // write guard as before: addToBlacklist/addToWhitelist can each fire
  // multiple times in quick succession (e.g. several players banned back-
  // to-back), and these saves are fire-and-forget rather than blocking.
  private saveWhitelist(): void {
    if (this.isSavingWhitelist) { this.saveWhitelistAgain = true; return; }
    // Mirror to the MySQL whitelist table too (no-op unless storage.type =
    // mysql). Independent of the JSON/document save below and fire-and-forget.
    this.mirrorWhitelistToDb();
    if (!this.storageAdapter) return; // not initialized yet - nothing to save to
    this.isSavingWhitelist = true;
    this.storageAdapter.write('whitelist', this.whitelist)
      .then(() => {
        this.isSavingWhitelist = false;
        this.logger.debug(`Whitelist saved: ${this.whitelist.ips.length} IPs`);
        if (this.saveWhitelistAgain) { this.saveWhitelistAgain = false; this.saveWhitelist(); }
      })
      .catch((e) => {
        this.isSavingWhitelist = false;
        this.logger.error('Failed to save whitelist', e);
        if (this.saveWhitelistAgain) { this.saveWhitelistAgain = false; this.saveWhitelist(); }
      });
  }

  // Save blacklist via the configured storage backend - same fire-and-
  // forget/debounce pattern as saveWhitelist above.
  private saveBlacklist(): void {
    if (this.isSavingBlacklist) { this.saveBlacklistAgain = true; return; }
    // Mirror to the MySQL blacklist table too (no-op unless storage.type =
    // mysql). Independent of the JSON/document save below and fire-and-forget.
    this.mirrorBlacklistToDb();
    if (!this.storageAdapter) return; // not initialized yet - nothing to save to
    this.isSavingBlacklist = true;
    this.storageAdapter.write('blacklist', this.blacklist)
      .then(() => {
        this.isSavingBlacklist = false;
        this.logger.debug(`Blacklist saved: ${this.blacklist.ips.length} IPs`);
        if (this.saveBlacklistAgain) { this.saveBlacklistAgain = false; this.saveBlacklist(); }
      })
      .catch((e) => {
        this.isSavingBlacklist = false;
        this.logger.error('Failed to save blacklist', e);
        if (this.saveBlacklistAgain) { this.saveBlacklistAgain = false; this.saveBlacklist(); }
      });
  }

  // Get whitelist statistics
  getWhitelistStats() { 
    return { 
      ips: this.whitelist.ips.length, 
      auto_added: this.whitelist.auto_added?.length || 0, 
      providers: this.whitelist.providers?.length || 0 
    }; 
  }

  // Get blacklist statistics
  getBlacklistStats() { 
    return { 
      ips: this.blacklist.ips.length, 
      auto_added: this.blacklist.auto_added?.length || 0 
    }; 
  }

  // Get all blacklisted IPs
  getAllBlacklistedIps(): string[] {
    return [...this.blacklist.ips];
  }

  // Get all blacklisted entries with details
  getBlacklistEntries(): BlacklistEntry[] {
    return [...this.blacklist.auto_added];
  }

  // Load custom blacklist from a file (for manual imports)
  async loadCustomBlacklist(filePath: string): Promise<number> {
    try {
      if (!fs.existsSync(filePath)) {
        this.logger.warn(`Blacklist file not found: ${filePath}`);
        return 0;
      }

      const content = fs.readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');
      const ips: string[] = [];
      
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//')) continue;
        
        // Check if line contains IP (with optional comment after space)
        const ipMatch = trimmed.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2})?)/);
        if (ipMatch) {
          ips.push(ipMatch[1]);
        }
      }

      if (ips.length > 0) {
        const added = this.addManyToBlacklist(ips, `Custom import from ${filePath}`, 'CustomFile');
        this.logger.info(`Loaded ${added} IPs from custom blacklist: ${filePath}`);
        return added;
      }
      
      return 0;
    } catch (error) {
      this.logger.error(`Failed to load custom blacklist: ${filePath}`, error);
      return 0;
    }
  }

  // Parse blacklist from text format (one IP per line, supports comments)
  parseBlacklistText(text: string): string[] {
    const lines = text.split('\n');
    const ips: string[] = [];
    
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//')) continue;
      
      const ipMatch = trimmed.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2})?)/);
      if (ipMatch) {
        ips.push(ipMatch[1]);
      }
    }
    
    return ips;
  }
}