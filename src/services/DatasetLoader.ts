// src/services/DatasetLoader.ts
//
// Custom IP/ASN dataset support - loads data/datasets (configurable via
// config.json -> datasets.directory) at startup and, optionally, on a
// timer, so an operator can drop their own block-list data in without
// touching code. Treated with the same trust level the project already
// gives its own curated bulk lists (ListUpdater) and
// VERIFIED_HOSTING_VPN_ASNS by default (see DatasetsConfig.mode) - this is
// data the operator deliberately placed there, not a guess.
//
// SUPPORTED LAYOUT: any mix of files and folders under the datasets
// directory, at any nesting depth, including zip archives (which may
// themselves contain folders, files, and further zips up to
// max_zip_depth). Any path under `datasets.exclude` is skipped entirely -
// see DatasetsConfig.exclude.
//
// SUPPORTED FORMATS (by extension):
//   .txt, .cidr        - one IP/CIDR/ASN per line, or a whitespace-
//                         separated multi-field line (e.g. "ip score" or
//                         "start_ip end_ip prefix count org ...") - the
//                         IP/CIDR/ASN/range fields are picked out of the
//                         rest per line the same way an un-headered CSV
//                         row is (see classifyFields). A URL scheme
//                         (scheme://) and a trailing :port are stripped
//                         before classifying a token, so proxy lists in
//                         "scheme://ip:port" or "ip:port" form work too.
//   .netset, .ipset     - FireHOL-style netsets and Linux `ipset save`
//                         dumps
//   .csv, .tsv          - column-aware (ip/cidr/asn headers recognized,
//                         plus start_ip/end_ip-style column pairs merged
//                         into one IP range); falls back to per-row
//                         generic classification (classifyFields) if no
//                         recognizable header is present. Streamed line by
//                         line regardless of file size.
//   .json               - arrays of strings, arrays of objects, or objects
//                         keyed by IP/CIDR/ASN; recognized field names are
//                         the same as the CSV/TSV column list. Files over
//                         LARGE_JSON_THRESHOLD_BYTES are assumed to be
//                         NDJSON (one JSON object per line) and streamed
//                         line by line instead of parsed as one document,
//                         since a single JSON.parse over a multi-hundred-
//                         MB string can exceed Node's max string length.
//   .mmdb               - MaxMind DB format; requires the optional
//                         "maxmind" package (`npm install maxmind`) -
//                         skipped with a clear log line if it isn't
//                         installed. Unlike every other format, an MMDB
//                         isn't pre-expanded into the in-memory index -
//                         it's kept open and queried live per connection
//                         (see lookupMmdb), since that's what the format
//                         is actually designed for.
//   .parquet            - requires the optional "parquetjs-lite" package
//                         (`npm install parquetjs-lite`); same graceful
//                         skip if missing. Columns are matched the same
//                         way as CSV headers, including start_ip/end_ip
//                         range pairs.
//   .bin                - a small documented convention (see parseBin
//                         below) since ".bin" isn't a standard list
//                         format: 5-byte records ([4-byte IPv4][1-byte
//                         prefix]) or, if the file size doesn't divide by
//                         5, bare 4-byte IPv4 host records.
//   anything else       - sniffed; treated as a plain line list if it
//                         looks like text, otherwise skipped.
//
// SIZE HANDLING: only formats that must be fully buffered before they can
// be parsed at all (.zip, .mmdb, .parquet, .bin) are subject to
// max_file_size_mb. Line/record-oriented formats (.txt, .cidr, .netset,
// .ipset, .csv, .tsv, and the sniffed-text fallback) are streamed a line
// at a time via forEachLine() regardless of size - a multi-GB CIDR/CSV
// dump loads in bounded memory. Zip *entries* are still size-capped, since
// extracting from a zip inherently means buffering that entry in memory.
//
// DEDUPLICATION: every IP/CIDR/ASN entry is deduplicated (a) against every
// other dataset entry seen in the same load pass, and (b) against what the
// project already knows (VERIFIED_HOSTING_VPN_ASNS) - see addEntry()
// below. Exact-duplicate entries are silently skipped and counted in
// getStats().duplicates_skipped. AS0 (IANA-reserved / "not routed" per RFC
// 7607) is never stored even if a dataset lists it explicitly.
//
// PERFORMANCE: IPv4 IP/CIDR/range entries are merged into the same sorted,
// disjoint, binary-searchable range representation ListManager already
// uses for its own curated static list - O(log n) per lookup regardless
// of how many datasets are loaded. ASN lookups use a Map the same way
// VERIFIED_HOSTING_VPN_ASNS_SET already does elsewhere in this project,
// since ASN lists are orders of magnitude smaller than the IP data.
// Loading itself is async and only ever runs at startup and on the
// configured reload timer - never on the player-connection hot path.
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { Logger } from '../utils/Logger';
import { DatasetsConfig, DatasetMatch, DatasetMatchType } from '../types';
import { VERIFIED_HOSTING_VPN_ASNS_SET } from './ProviderLists';
import { DEFAULT_DATASETS_CONFIG } from '../config/DatasetsDefaults';
import { RangeTable } from './RangeTable';
import { RangeIndexStore, Ipv6Entry, RangeWriteSession } from './RangeIndexStore';

type ParsedToken =
  | { kind: 'ip'; value: string; isV6: boolean }
  | { kind: 'cidr'; value: string; isV6: boolean }
  | { kind: 'asn'; value: number }
  | { kind: 'range'; startNum: number; endNum: number } // IPv4 start/end pair (e.g. CSV start_ip/end_ip columns)
  | null;

type ColumnHint = 'ip' | 'cidr' | 'asn';

interface LoadStats {
  files: number;
  zips: number;
  added: number;
  duplicates: number;
  skipped: number;
  errors: number;
}

interface DelimitedHeader {
  headerMap: Map<number, ColumnHint>;
  rangeStartIdx: number | null;
  rangeEndIdx: number | null;
  hasHeader: boolean;
}

// Per-file accumulation state, created fresh for every dataset file (or,
// for a zip, shared across all of that zip's inner entries) and threaded
// explicitly through every parser method below instead of living as shared
// instance state. This is what makes skip-unchanged-files and per-file
// incremental DB replace possible: each file's contribution can be
// persisted independently the moment that one file finishes, rather than
// all files funneling into one global buffer that's indistinguishable by
// source once merged.
//
// IPv4 ip/cidr/range entries are streamed straight to rangeSession
// (RangeIndexStore.RangeWriteSession) as they're classified, instead of
// being accumulated into a whole-file array first - see that interface's
// doc comment for why (peak memory was O(file size) before this, and this
// project's real datasets include multi-million-line files). IPv6/ASN
// entries stay buffered here since their volume is orders of magnitude
// smaller (this project's own datasets consistently produce thousands, not
// millions, of those).
interface FileParseContext {
  rangeSession: RangeWriteSession;
  pendingIpv6: Ipv6Entry[];
  pendingExactKeys: Set<string>;
  pendingAsn: Map<number, string>; // asn -> attribution label (e.g. "asn_ovh.txt")
  // FP-hardening: running total of IPv4 addresses this file contributes -
  // used purely to WARN (never skip) when a single file covers so much
  // address space it's almost certainly a geo/reference database rather
  // than an abuse list (the name-based `exclude` config can't catch a
  // renamed file; this catches it from the data itself).
  addressCount: number;
}

const IPV4_CIDR_RE = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/;
const IPV4_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

// A single JSON.parse over a document bigger than this risks exceeding
// Node's max string length on a readFileSync'd buffer (~512MB on typical
// builds) - files over the threshold are instead assumed to be NDJSON
// (one JSON object per line, which is what every real-world dataset this
// large has turned out to be) and streamed line by line.
const LARGE_JSON_THRESHOLD_BYTES = 400 * 1024 * 1024;

// Common non-data files an operator might reasonably leave alongside
// datasets (a README, a .gitkeep, notes, etc.) - explicitly never sniffed
// as a line list, since free-text prose would otherwise get misread as a
// pile of garbage IP/ASN entries via the same-file "no recognizable
// IP/CIDR/ASN -> skip" fallback plain .txt files intentionally rely on.
const IGNORED_EXTENSIONS = new Set([
  '.md', '.markdown', '.rst', '.log', '.yml', '.yaml', '.ini', '.conf',
  '.cfg', '.gitignore', '.gitattributes', '.gitkeep', '.editorconfig',
  '.license', '.lock', '.ds_store', '.png', '.jpg', '.jpeg', '.gif',
  '.pdf', '.doc', '.docx', '.xlsx', '.xls', '.sqlite', '.db',
]);

// Recognized CSV/TSV header names and JSON object keys, mapped to what
// kind of data the column/field holds.
const COLUMN_HINTS: Record<string, ColumnHint> = {
  ip: 'ip', ip_address: 'ip', ipaddress: 'ip', address: 'ip', addr: 'ip', host: 'ip',
  cidr: 'cidr', network: 'cidr', range: 'cidr', subnet: 'cidr', prefix: 'cidr', block: 'cidr',
  asn: 'asn', as: 'asn', as_number: 'asn', asnumber: 'asn', autonomous_system: 'asn',
  autonomous_system_number: 'asn',
};

// Column names that hold one half of an IPv4 range (e.g. IP-to-ASN/proxy
// bulk exports laid out as "start_ip,end_ip,asn,name" rows) - recognized
// separately from COLUMN_HINTS since a start/end pair only means anything
// combined, not as two independent IPs.
const RANGE_START_COLUMNS = new Set(['start_ip', 'startip', 'ip_start', 'ipstart', 'range_start', 'rangestart', 'ip_from', 'ipfrom']);
const RANGE_END_COLUMNS = new Set(['end_ip', 'endip', 'ip_end', 'ipend', 'range_end', 'rangeend', 'ip_to', 'ipto']);

export class DatasetLoader {
  private static instance: DatasetLoader | null = null;
  private logger: Logger;
  private store: RangeIndexStore;
  private config: DatasetsConfig = DEFAULT_DATASETS_CONFIG;
  private loaded: boolean = false;
  private loading: boolean = false;
  private lastLoadedAt: string | null = null;
  private reloadTimer: NodeJS.Timeout | null = null;

  // --- Built indexes - these are the only things read on the hot,
  // per-connection path, so they're kept as cheap as possible. Rebuilt from
  // RangeIndexStore (see rebuildRuntimeIndexFromStore) after every load
  // pass - never accumulated in-place across files, so a skipped-unchanged
  // file's previously-persisted contribution is included exactly the same
  // as a freshly-reparsed one. ---
  private rangeTable: RangeTable = RangeTable.EMPTY;
  private ipv6ExactSet: Set<string> = new Set();
  private ipv6Cidrs: string[] = []; // linear-scanned - IPv6 datasets are typically far smaller
  private asnSourceMap: Map<number, string> = new Map();
  private mmdbReaders: Array<{ name: string; reader: any }> = [];

  private stats: LoadStats = { files: 0, zips: 0, added: 0, duplicates: 0, skipped: 0, errors: 0 };
  // Invoked after every completed loadAll() pass (startup + every
  // auto-reload tick). IpChecker registers the dataset-provenance blacklist
  // prune here (see IpChecker.pruneStaleDatasetBans) so removing a bad
  // dataset file actually un-blacklists its victims on the next (re)load
  // instead of leaving those 'Dataset'-method bans permanent forever.
  private onLoadedCallback: (() => void) | null = null;
  // Files whose size+mtime matched their last successful import (see
  // import_file_state in RangeIndexStore) - never re-read, re-parsed, or
  // re-persisted. Tracked separately from stats.skipped (which means
  // "recognized but excluded/unparseable"), since this is the intended
  // fast path on every restart/reload once a dataset directory stabilizes.
  private filesUnchanged: number = 0;

  private constructor() {
    this.logger = Logger.getInstance();
    this.store = RangeIndexStore.getInstance();
  }

  static getInstance(): DatasetLoader {
    if (!DatasetLoader.instance) DatasetLoader.instance = new DatasetLoader();
    return DatasetLoader.instance;
  }

  onLoaded(cb: () => void): void {
    this.onLoadedCallback = cb;
  }

  private async newContext(fileKey: string): Promise<FileParseContext> {
    return {
      rangeSession: await this.store.beginDatasetRangeSession(fileKey),
      pendingIpv6: [],
      pendingExactKeys: new Set(),
      pendingAsn: new Map(),
      addressCount: 0,
    };
  }

  // ========================================================================
  // PUBLIC QUERY API (called from IpChecker - all synchronous except the
  // MMDB path, and even that never does network/disk I/O per call, only a
  // read against an already-open memory-mapped buffer)
  // ========================================================================

  isIpMatch(ip: string): DatasetMatch | null {
    if (!this.loaded) return null;
    if (ip.includes(':')) {
      const lower = ip.toLowerCase();
      if (this.ipv6ExactSet.has(lower)) return { source: 'datasets', type: 'ip', value: ip };
      for (const cidr of this.ipv6Cidrs) {
        if (this.ipv6InCidr(lower, cidr)) return { source: 'datasets', type: 'cidr', value: cidr };
      }
      return null;
    }
    const num = this.ipv4ToNumber(ip);
    if (num === null) return null;
    const found = this.rangeTable.findRange(num);
    if (!found) return null;
    const [start, end] = found;
    // A range that collapsed down to exactly one address came from a
    // dataset "single IP" entry; anything wider was a genuine CIDR (or the
    // merge of several overlapping ones) - reported as a plain address
    // range rather than forcing it back into (possibly inaccurate) CIDR
    // notation.
    const type: DatasetMatchType = start === end ? 'ip' : 'cidr';
    const value = type === 'ip' ? ip : `${this.numberToIp(start)}-${this.numberToIp(end)}`;
    return { source: 'datasets', type, value };
  }

  isAsnMatch(asn: number): DatasetMatch | null {
    const source = this.asnSourceMap.get(asn);
    return source ? { source, type: 'asn', value: `AS${asn}` } : null;
  }

  // Queries every loaded MMDB in order and returns the first hit. Each
  // lookup is a synchronous read against an in-memory buffer (that's how
  // the MMDB format itself works - it's designed for exactly this), so
  // this is safe to call on every connection without adding latency.
  lookupMmdb(ip: string): DatasetMatch | null {
    for (const { name, reader } of this.mmdbReaders) {
      try {
        const record = reader.get(ip);
        if (record) {
          const asn = record.autonomous_system_number || record.asn || null;
          const org = record.autonomous_system_organization || record.organization || record.isp || null;
          const label = org || (asn ? `AS${asn}` : 'match');
          return { source: name, type: 'mmdb', value: String(label) };
        }
      } catch {
        // Malformed lookup against this particular DB for this particular
        // IP (e.g. an IPv4-only DB queried with an IPv6 address) - try the
        // next loaded MMDB rather than failing the whole check.
      }
    }
    return null;
  }

  isEnabled(): boolean {
    return this.config.enabled;
  }

  getStats() {
    return {
      enabled: this.config.enabled,
      mode: this.config.mode,
      directory: this.config.directory,
      loaded: this.loaded,
      last_loaded_at: this.lastLoadedAt,
      files_loaded: this.stats.files,
      files_unchanged: this.filesUnchanged,
      zips_loaded: this.stats.zips,
      ipv4_ranges: this.rangeTable.size,
      ipv6_exact: this.ipv6ExactSet.size,
      ipv6_cidrs: this.ipv6Cidrs.length,
      asns: this.asnSourceMap.size,
      mmdb_databases: this.mmdbReaders.length,
      duplicates_skipped: this.stats.duplicates,
      entries_skipped: this.stats.skipped,
      parse_errors: this.stats.errors,
    };
  }

  // ========================================================================
  // LOADING
  // ========================================================================

  // Loads whatever was persisted from the last successful import pass -
  // near-instant (a handful of bulk ordered SELECTs, zero file parsing), so
  // the very first player connections after a restart already have dataset
  // data available instead of racing an empty index against a full reparse
  // of data/datasets. Called synchronously from the startup sequence
  // (index.ts), before loadAll() runs in the background. MMDB readers are
  // the one thing this can't restore (a live reader can't round-trip
  // through the range store) - those only become available once loadAll()
  // itself has run at least once.
  async loadFromStore(config: DatasetsConfig): Promise<void> {
    this.config = config;
    if (!config.enabled) return;
    await this.rebuildRuntimeIndexFromStore();
    if (this.rangeTable.size > 0 || this.ipv6ExactSet.size > 0 || this.ipv6Cidrs.length > 0 || this.asnSourceMap.size > 0) {
      this.loaded = true;
      this.logger.info(
        `DatasetLoader: loaded ${this.rangeTable.size} IPv4 ranges, ${this.ipv6ExactSet.size + this.ipv6Cidrs.length} IPv6 entries, ` +
        `${this.asnSourceMap.size} ASNs from local store (instant, no file parsing)`
      );
    }
  }

  private async rebuildRuntimeIndexFromStore(): Promise<void> {
    const { starts, ends } = await this.store.loadDatasetRangesUnion();
    this.rangeTable = RangeTable.fromSortedPairs(starts, ends);
    const ipv6Rows = await this.store.loadDatasetIpv6Union();
    const exact = new Set<string>();
    const cidrs: string[] = [];
    for (const row of ipv6Rows) {
      if (row.kind === 'ip') exact.add(row.value); else cidrs.push(row.value);
    }
    this.ipv6ExactSet = exact;
    this.ipv6Cidrs = cidrs;
    this.asnSourceMap = await this.store.loadDatasetAsnUnion();
  }

  async loadAll(config: DatasetsConfig): Promise<void> {
    this.config = config;
    if (this.loading) {
      this.logger.debug('DatasetLoader: a load is already in progress, skipping this call');
      return;
    }
    if (!config.enabled) {
      this.logger.info('DatasetLoader: disabled via config (datasets.enabled = false)');
      return;
    }

    const dir = path.isAbsolute(config.directory) ? config.directory : path.join(process.cwd(), config.directory);
    if (!fs.existsSync(dir)) {
      try {
        fs.mkdirSync(dir, { recursive: true });
        this.logger.info(`DatasetLoader: created empty ${config.directory} - drop txt/csv/tsv/json/netset/ipset/cidr/mmdb/parquet/bin files (or zips of them, in any folder structure) in there`);
      } catch (e) {
        this.logger.warn(`DatasetLoader: ${config.directory} doesn't exist and couldn't be created`, e);
      }
      return;
    }

    this.loading = true;
    const start = Date.now();
    this.mmdbReaders = [];
    this.stats = { files: 0, zips: 0, added: 0, duplicates: 0, skipped: 0, errors: 0 };
    this.filesUnchanged = 0;

    try {
      const files = this.collectFiles(dir, dir);
      await this.loadFilesConcurrently(files);
      await this.rebuildRuntimeIndexFromStore();
      this.loaded = true;
      this.lastLoadedAt = new Date().toISOString();
      const ipv6Total = this.ipv6ExactSet.size + this.ipv6Cidrs.length;
      this.logger.info(
        `DatasetLoader: processed ${files.length} files (${this.stats.files} parsed, ${this.filesUnchanged} unchanged, ${this.stats.zips} zips) in ${Date.now() - start}ms - ` +
        `${this.rangeTable.size} IPv4 ranges, ${ipv6Total} IPv6 entries, ${this.asnSourceMap.size} ASNs, ` +
        `${this.mmdbReaders.length} MMDB databases ` +
        `(${this.stats.duplicates} duplicates skipped, ${this.stats.skipped} entries skipped, ${this.stats.errors} errors)`
      );
      if (this.onLoadedCallback) {
        try { this.onLoadedCallback(); } catch (e) { this.logger.warn('DatasetLoader: onLoaded callback failed', e); }
      }
    } catch (e) {
      this.logger.error('DatasetLoader: load pass failed', e);
    } finally {
      this.loading = false;
    }
  }

  startAutoReload(config: DatasetsConfig): void {
    this.stopAutoReload();
    if (!config.enabled || !config.reload_interval_minutes || config.reload_interval_minutes <= 0) return;
    const ms = config.reload_interval_minutes * 60 * 1000;
    this.reloadTimer = setInterval(() => {
      this.loadAll(config).catch((e) => this.logger.error('DatasetLoader: auto-reload failed', e));
    }, ms);
    // Don't let this timer keep the process alive on its own.
    if (typeof (this.reloadTimer as any).unref === 'function') (this.reloadTimer as any).unref();
    this.logger.info(`DatasetLoader: auto-reload enabled every ${config.reload_interval_minutes} minutes`);
  }

  stopAutoReload(): void {
    if (this.reloadTimer) {
      clearInterval(this.reloadTimer);
      this.reloadTimer = null;
    }
  }

  // rootDir is the configured datasets directory itself (constant across a
  // whole walk) - used to compute the exclude-relative path at every level
  // without re-deriving it on each recursive call. Synchronous (readdirSync/
  // statSync are already sync) and side-effect-free - just builds the flat
  // file list up front so loadFilesConcurrently below can fan the actual
  // (async) parsing out instead of loading one file at a time.
  private collectFiles(dir: string, rootDir: string): Array<{ filePath: string; size: number }> {
    const out: Array<{ filePath: string; size: number }> = [];
    let items: string[];
    try {
      items = fs.readdirSync(dir);
    } catch (e) {
      this.logger.warn(`DatasetLoader: cannot read directory ${dir}`, e);
      return out;
    }
    for (const item of items) {
      const full = path.join(dir, item);
      const rel = path.relative(rootDir, full).split(path.sep).join('/');
      if (this.isExcluded(rel)) {
        this.logger.debug(`DatasetLoader: skipping excluded path ${rel}`);
        continue;
      }
      let st: fs.Stats;
      try {
        st = fs.statSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        out.push(...this.collectFiles(full, rootDir));
      } else if (st.isFile()) {
        out.push({ filePath: full, size: st.size });
      }
    }
    return out;
  }

  // A real-world datasets directory tends to be a handful of huge files
  // (streamed one line at a time regardless) alongside hundreds of small-
  // to-medium ones (a few KB to a few MB each) - see the SUPPORTED LAYOUT
  // note at the top of this file. Loading those one at a time left most of
  // the wall-clock time sitting in per-file I/O wait (open/seek/first-read
  // latency) with the event loop otherwise idle. Every file only ever
  // mutates the shared pending buffers through the synchronous addEntry()
  // path, and JS's cooperative scheduling means two files' callbacks can
  // never actually interleave mid-mutation (only at their own await
  // points), so running a bounded batch concurrently is race-free and
  // overlaps that I/O the same way ListUpdater's download batching does
  // (see updateAllLists) - diminishing returns on the one-huge-file case,
  // which is still bottlenecked on its own single stream either way, but a
  // large win on directories with many small/medium files.
  private async loadFilesConcurrently(files: Array<{ filePath: string; size: number }>): Promise<void> {
    const CONCURRENCY = 8;
    for (let i = 0; i < files.length; i += CONCURRENCY) {
      const batch = files.slice(i, i + CONCURRENCY);
      await Promise.all(batch.map((f) => this.loadFileSafe(f.filePath, f.size)));
    }
  }

  private isExcluded(relPath: string): boolean {
    const segments = relPath.split('/');
    const topLevel = segments[0];
    const base = segments[segments.length - 1];
    return (this.config.exclude || []).some((ex) => {
      if (relPath === ex || relPath.startsWith(`${ex}/`)) return true;
      // A bare (no "/") exclude entry also matches by prefix against the
      // top-level path segment and the file's own basename, so a
      // periodically re-downloaded, differently-dated folder/file (e.g.
      // "GeoLite2-ASN-CSV_20260809") stays excluded without editing config.
      if (!ex.includes('/')) return topLevel.startsWith(ex) || base.startsWith(ex);
      return false;
    });
  }

  private async loadFileSafe(filePath: string, size: number): Promise<void> {
    const ext = path.extname(filePath).toLowerCase();
    // Only formats that must be fully buffered before they can be parsed
    // at all are subject to the size cap - everything else is streamed a
    // line/record at a time below, so an operator dropping in a multi-GB
    // CIDR/CSV dump doesn't need to raise max_file_size_mb to load it.
    const mustBuffer = ext === '.zip' || ext === '.mmdb' || ext === '.parquet' || ext === '.bin';
    if (mustBuffer) {
      const maxBytes = this.config.max_file_size_mb * 1024 * 1024;
      if (size > maxBytes) {
        this.logger.warn(`DatasetLoader: skipping ${filePath} (${(size / 1024 / 1024).toFixed(1)}MB exceeds max_file_size_mb=${this.config.max_file_size_mb})`);
        this.stats.skipped++;
        return;
      }
    }

    // Skip-unchanged: a file whose size+mtime match its last successful
    // import is re-parsed for nothing - its rows are already correct in
    // RangeIndexStore from that import (see persistContext below). This is
    // the fast path on every restart/reload tick once a dataset directory
    // has stabilized - real multi-hundred-MB dataset files change rarely.
    // MMDB is the one exception: a live reader can't be persisted/restored
    // from the DB, so it must always be (cheaply) reopened.
    let mtimeMs = 0;
    if (ext !== '.mmdb') {
      try {
        mtimeMs = fs.statSync(filePath).mtimeMs;
        if (await this.store.isFileUnchanged(filePath, size, mtimeMs)) {
          this.filesUnchanged++;
          return;
        }
      } catch {
        // stat failed - fall through and attempt the parse anyway rather
        // than silently dropping a file we can't confirm is unchanged.
      }
    }

    const ctx = await this.newContext(filePath);
    try {
      if (ext === '.zip') {
        await this.loadZipFile(filePath, 0, ctx);
        this.stats.zips++;
      } else {
        await this.loadRegularFile(filePath, ext, size, ctx);
        this.stats.files++;
      }
      await this.persistContext(filePath, ctx);
      if (ext !== '.mmdb') await this.store.markFileImported(filePath, size, mtimeMs);
    } catch (e) {
      this.stats.errors++;
      this.logger.warn(`DatasetLoader: failed to load ${filePath}: ${(e as Error).message}`);
    }
  }

  // Finalizes one file's (or, for a zip, all of that zip's inner entries')
  // accumulated context into DB rows, keyed by this outer file's path -
  // this is the incremental-replace granularity: reparsing this file later
  // replaces exactly these rows, and none of any other file's. IPv4 ranges
  // were already streamed to rangeSession as they were classified (see
  // FileParseContext's doc comment) - finish() just flushes the last
  // partial batch and handles the zero-entries case. IPv6/ASN are still
  // buffered-then-written here (their volume doesn't warrant the same
  // streaming treatment) - always replaced (even with empty arrays) so an
  // entry that used to exist here but no longer does doesn't linger forever.
  private async persistContext(filePath: string, ctx: FileParseContext): Promise<void> {
    // Coverage sanity warning (never a skip - the operator may genuinely
    // mean it): a single file contributing more than ~50M IPv4 addresses
    // (roughly 3x a /8) is far beyond any real VPN/proxy/hosting corpus and
    // almost always means a geo/reference database slipped past the
    // name-based `exclude` config under a new name.
    const COVERAGE_WARN_THRESHOLD = 50_000_000;
    if (ctx.addressCount > COVERAGE_WARN_THRESHOLD) {
      this.logger.warn(
        `DatasetLoader: ${path.basename(filePath)} covers ${(ctx.addressCount / 1e6).toFixed(0)}M IPv4 addresses - ` +
        `this looks like a geo/reference database, not an abuse list. Consider adding it to datasets.exclude ` +
        `(in 'instant' mode a file like this can ban enormous swaths of legitimate players).`
      );
    }
    await ctx.rangeSession.finish();
    await this.store.replaceDatasetIpv6ForSource(filePath, ctx.pendingIpv6);
    const asnEntries = Array.from(ctx.pendingAsn.entries()).map(([asn, label]) => ({ asn, label }));
    await this.store.replaceDatasetAsnForFile(filePath, asnEntries);
  }

  private async loadRegularFile(filePath: string, ext: string, size: number, ctx: FileParseContext): Promise<void> {
    const name = path.basename(filePath);
    switch (ext) {
      case '.txt':
      case '.cidr':
        await this.parseLineListFile(filePath, name, ctx);
        break;
      case '.netset':
      case '.ipset':
        await this.parseIpsetOrNetsetFile(filePath, name, ctx);
        break;
      case '.csv':
        await this.parseDelimitedFile(filePath, ',', name, ctx);
        break;
      case '.tsv':
        await this.parseDelimitedFile(filePath, '\t', name, ctx);
        break;
      case '.json':
        await this.parseJsonFile(filePath, name, size, ctx);
        break;
      case '.bin':
        this.parseBin(fs.readFileSync(filePath), name, ctx);
        break;
      case '.mmdb':
        await this.parseMmdbFile(filePath, name);
        break;
      case '.parquet':
        await this.parseParquetFile(filePath, name, ctx);
        break;
      default:
        if (IGNORED_EXTENSIONS.has(ext)) {
          this.logger.debug(`DatasetLoader: skipping non-data file ${name}`);
        } else if (this.looksLikeText(filePath)) {
          await this.parseLineListFile(filePath, name, ctx);
        } else {
          this.logger.debug(`DatasetLoader: skipping unrecognized file ${name}`);
          this.stats.skipped++;
        }
    }
  }

  // Streams a file's lines without ever holding the whole thing in memory
  // - the only way a multi-GB dataset file can be loaded at all. Hand-rolled
  // instead of readline: readline's 'line' event (or its async-iterator
  // form) yields back to the event loop once per line, and on the
  // multi-hundred-MB/multi-GB files this loader is explicitly designed to
  // stream (see file header), that per-line scheduling overhead ends up
  // dwarfing the actual parse work. Reading in large chunks and splitting
  // on '\n' ourselves keeps the same bounded-memory guarantee (only ever
  // holding one chunk plus a small carry-over of the trailing partial
  // line) while cutting wall-clock time substantially on those files.
  private async forEachLine(filePath: string, onLine: (line: string) => void): Promise<void> {
    const stream = fs.createReadStream(filePath, { encoding: 'utf-8', highWaterMark: 1024 * 1024 });
    let carry = '';
    for await (const chunk of stream as AsyncIterable<string>) {
      carry += chunk;
      let start = 0;
      let nl = carry.indexOf('\n', start);
      while (nl !== -1) {
        const end = carry.charCodeAt(nl - 1) === 13 /* '\r' */ ? nl - 1 : nl; // strip trailing \r (CRLF)
        onLine(carry.slice(start, end));
        start = nl + 1;
        nl = carry.indexOf('\n', start);
      }
      carry = start > 0 ? carry.slice(start) : carry;
    }
    if (carry.length > 0) {
      const end = carry.charCodeAt(carry.length - 1) === 13 ? carry.length - 1 : carry.length;
      onLine(carry.slice(0, end));
    }
  }

  // --- Zip handling (adm-zip is a hard dependency - see package.json -
  // but still lazily required with a clear fallback message so a dataset
  // problem can never crash the server if something's wrong with the
  // install) -----------------------------------------------------------
  private async loadZipFile(filePath: string, depth: number, ctx: FileParseContext): Promise<void> {
    if (depth > this.config.max_zip_depth) {
      this.logger.warn(`DatasetLoader: zip nesting exceeds max_zip_depth=${this.config.max_zip_depth}, skipping ${filePath}`);
      return;
    }
    let AdmZip: any;
    try {
      AdmZip = require('adm-zip');
    } catch {
      this.logger.warn(`DatasetLoader: found ${filePath} but the "adm-zip" package isn't installed - run npm install to enable zip support`);
      this.stats.skipped++;
      return;
    }
    let zip: any;
    try {
      zip = new AdmZip(filePath);
    } catch (e) {
      this.stats.errors++;
      this.logger.warn(`DatasetLoader: failed to open zip ${filePath}: ${(e as Error).message}`);
      return;
    }
    await this.consumeZipEntries(zip, path.basename(filePath), depth, ctx);
  }

  private async loadZipBuffer(buffer: Buffer, name: string, depth: number, ctx: FileParseContext): Promise<void> {
    if (depth > this.config.max_zip_depth) {
      this.logger.warn(`DatasetLoader: nested zip exceeds max_zip_depth=${this.config.max_zip_depth}, skipping ${name}`);
      return;
    }
    let AdmZip: any;
    try {
      AdmZip = require('adm-zip');
    } catch {
      return;
    }
    let zip: any;
    try {
      zip = new AdmZip(buffer);
    } catch (e) {
      this.stats.errors++;
      this.logger.warn(`DatasetLoader: failed to open nested zip ${name}: ${(e as Error).message}`);
      return;
    }
    await this.consumeZipEntries(zip, name, depth, ctx);
  }

  private async consumeZipEntries(zip: any, zipLabel: string, depth: number, ctx: FileParseContext): Promise<void> {
    const entries = zip.getEntries();
    const maxBytes = this.config.max_file_size_mb * 1024 * 1024;
    for (const entry of entries) {
      if (entry.isDirectory) continue;
      const entryLabel = `${zipLabel}::${entry.entryName}`;
      const ext = path.extname(entry.entryName).toLowerCase();
      // Zip-bomb guard: the central directory's declared uncompressed size
      // (entry.header.size) is checked BEFORE calling getData() below,
      // which is what actually inflates the entry into memory. A crafted
      // entry can have a tiny compressed size but a declared uncompressed
      // size of many GB - checking only *after* getData() (as this used to)
      // means the damage (allocating/inflating that whole buffer) is
      // already done by the time the check runs. adm-zip itself allocates
      // its output buffer from this same declared size, so rejecting here
      // costs nothing extra and skips the allocation entirely.
      const declaredSize = entry.header?.size;
      if (typeof declaredSize === 'number' && declaredSize > maxBytes) {
        this.logger.warn(`DatasetLoader: skipping zip entry ${entryLabel} (declared uncompressed size ${(declaredSize / 1024 / 1024).toFixed(1)}MB exceeds max_file_size_mb=${this.config.max_file_size_mb})`);
        this.stats.skipped++;
        continue;
      }
      let buffer: Buffer;
      try {
        buffer = entry.getData();
      } catch (e) {
        this.stats.errors++;
        this.logger.warn(`DatasetLoader: failed to extract ${entryLabel}: ${(e as Error).message}`);
        continue;
      }
      if (buffer.length > maxBytes) {
        this.logger.warn(`DatasetLoader: skipping zip entry ${entryLabel} (exceeds max_file_size_mb=${this.config.max_file_size_mb})`);
        this.stats.skipped++;
        continue;
      }
      if (ext === '.zip') {
        await this.loadZipBuffer(buffer, entryLabel, depth + 1, ctx);
        this.stats.zips++;
        continue;
      }
      await this.loadBufferContent(buffer, entryLabel, ext, ctx);
      this.stats.files++;
    }
  }

  private async loadBufferContent(buffer: Buffer, name: string, ext: string, ctx: FileParseContext): Promise<void> {
    try {
      switch (ext) {
        case '.txt':
        case '.cidr':
          this.parseLineListContent(buffer.toString('utf-8'), name, ctx);
          break;
        case '.netset':
        case '.ipset':
          this.parseIpsetOrNetsetContent(buffer.toString('utf-8'), name, ctx);
          break;
        case '.csv':
          this.parseDelimitedContent(buffer.toString('utf-8'), ',', name, ctx);
          break;
        case '.tsv':
          this.parseDelimitedContent(buffer.toString('utf-8'), '\t', name, ctx);
          break;
        case '.json':
          this.parseJsonContent(buffer.toString('utf-8'), name, ctx);
          break;
        case '.bin':
          this.parseBin(buffer, name, ctx);
          break;
        case '.mmdb':
          await this.parseMmdbBuffer(buffer, name);
          break;
        case '.parquet':
          await this.parseParquetBuffer(buffer, name, ctx);
          break;
        default:
          if (IGNORED_EXTENSIONS.has(ext)) {
            this.logger.debug(`DatasetLoader: skipping non-data zip entry ${name}`);
          } else if (this.looksLikeTextBuffer(buffer)) {
            this.parseLineListContent(buffer.toString('utf-8'), name, ctx);
          } else {
            this.stats.skipped++;
          }
      }
    } catch (e) {
      this.stats.errors++;
      this.logger.warn(`DatasetLoader: failed to parse zip entry ${name}: ${(e as Error).message}`);
    }
  }

  // ========================================================================
  // FORMAT PARSERS
  // ========================================================================

  // --- Plain line lists (.txt/.cidr and the sniffed-text fallback) -------

  private parseLineListLine(rawLine: string, sourceName: string, ctx: FileParseContext): void {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//') || trimmed.startsWith(';')) return;
    // Strip trailing inline comments (either "# ..." or "; ..." - the
    // latter is how Spamhaus's own DROP/EDROP lists annotate each CIDR).
    const token = trimmed.split(/\s+[#;]/)[0].trim();
    if (!token) return;
    if (/\s/.test(token)) {
      // A multi-field line (e.g. "1.2.3.4  10" score lists, or
      // "start_ip end_ip prefix count org country contact" summaries) -
      // classify field by field/pair the same way an un-headered CSV row
      // is, instead of failing to parse as a single token.
      this.classifyFields(token.split(/\s+/), sourceName, ctx);
      return;
    }
    const parsed = this.classifyToken(token, sourceName, null);
    this.recordToken(parsed, sourceName, ctx);
  }

  private async parseLineListFile(filePath: string, sourceName: string, ctx: FileParseContext): Promise<void> {
    await this.forEachLine(filePath, (line) => this.parseLineListLine(line, sourceName, ctx));
  }

  private parseLineListContent(content: string, sourceName: string, ctx: FileParseContext): void {
    for (const rawLine of content.split(/\r?\n/)) this.parseLineListLine(rawLine, sourceName, ctx);
  }

  // --- FireHOL-style netsets (plain CIDR/IP per line) and Linux
  // `ipset save` dumps (`create <name> ...` header lines + `add <name>
  // <ip-or-cidr>` data lines) - both are common enough to warrant their
  // own extensions even though a netset is really just a restricted line
  // list. ------------------------------------------------------------------

  private parseIpsetOrNetsetLine(rawLine: string, sourceName: string, ctx: FileParseContext): void {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('#')) return;
    if (/^(create|COMMIT|flush)\b/i.test(trimmed)) return; // ipset control lines, not data
    const addMatch = trimmed.match(/^add\s+\S+\s+(\S+)/i);
    const token = addMatch ? addMatch[1] : trimmed.split(/\s+/)[0];
    const parsed = this.classifyIpLike(token);
    this.recordToken(parsed, sourceName, ctx);
  }

  private async parseIpsetOrNetsetFile(filePath: string, sourceName: string, ctx: FileParseContext): Promise<void> {
    await this.forEachLine(filePath, (line) => this.parseIpsetOrNetsetLine(line, sourceName, ctx));
  }

  private parseIpsetOrNetsetContent(content: string, sourceName: string, ctx: FileParseContext): void {
    for (const rawLine of content.split(/\r?\n/)) this.parseIpsetOrNetsetLine(rawLine, sourceName, ctx);
  }

  private parseBin(buffer: Buffer, sourceName: string, ctx: FileParseContext): void {
    // Documented convention (there's no universal ".bin" IP-list standard):
    //   - size % 5 === 0  -> records of [4-byte BE IPv4][1-byte prefix
    //     0-32] (prefix 32 = single host)
    //   - else size % 4 === 0 -> bare 4-byte BE IPv4 host records
    //   - anything else -> unrecognized, skipped
    if (buffer.length === 0) return;
    if (buffer.length % 5 === 0) {
      for (let i = 0; i < buffer.length; i += 5) {
        const ip = `${buffer[i]}.${buffer[i + 1]}.${buffer[i + 2]}.${buffer[i + 3]}`;
        const prefix = buffer[i + 4];
        if (prefix > 32) {
          this.stats.errors++;
          continue;
        }
        const token: ParsedToken = prefix === 32
          ? { kind: 'ip', value: ip, isV6: false }
          : { kind: 'cidr', value: `${ip}/${prefix}`, isV6: false };
        this.recordToken(token, sourceName, ctx);
      }
    } else if (buffer.length % 4 === 0) {
      for (let i = 0; i < buffer.length; i += 4) {
        const ip = `${buffer[i]}.${buffer[i + 1]}.${buffer[i + 2]}.${buffer[i + 3]}`;
        this.recordToken({ kind: 'ip', value: ip, isV6: false }, sourceName, ctx);
      }
    } else {
      this.logger.warn(`DatasetLoader: ${sourceName} doesn't match the supported .bin layout (size must be a multiple of 4 or 5 bytes) - skipped`);
      this.stats.skipped++;
    }
  }

  private splitDelimited(line: string, delimiter: string): string[] {
    const out: string[] = [];
    let cur = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') {
        if (inQuotes && line[i + 1] === '"') { cur += '"'; i++; }
        else inQuotes = !inQuotes;
      } else if (ch === delimiter && !inQuotes) {
        out.push(cur);
        cur = '';
      } else {
        cur += ch;
      }
    }
    out.push(cur);
    return out.map((s) => s.trim());
  }

  // Inspects a would-be header row: any cell matching a known IP/CIDR/ASN
  // column name is recorded in headerMap; a start_ip/end_ip-style pair is
  // recorded separately as a range. If nothing recognizable is found at
  // all, the caller treats this (and every other) row as plain data.
  private detectDelimitedHeader(headerLine: string, delimiter: string): DelimitedHeader {
    const cells = this.splitDelimited(headerLine, delimiter);
    const headerMap = new Map<number, ColumnHint>();
    let rangeStartIdx: number | null = null;
    let rangeEndIdx: number | null = null;
    cells.forEach((cell, idx) => {
      const key = cell.toLowerCase().replace(/[^a-z0-9_]/g, '');
      const hint = COLUMN_HINTS[key];
      if (hint) headerMap.set(idx, hint);
      else if (RANGE_START_COLUMNS.has(key)) rangeStartIdx = idx;
      else if (RANGE_END_COLUMNS.has(key)) rangeEndIdx = idx;
    });
    const hasHeader = headerMap.size > 0 || (rangeStartIdx !== null && rangeEndIdx !== null);
    return { headerMap, rangeStartIdx, rangeEndIdx, hasHeader };
  }

  private processDelimitedRow(line: string, delimiter: string, sourceName: string, header: DelimitedHeader, ctx: FileParseContext): void {
    const cells = this.splitDelimited(line, delimiter);
    if (!header.hasHeader) {
      // No recognizable header - fall back to classifying the row the
      // same way a multi-field line-list line is (still delimiter-aware,
      // so multi-column unlabeled data doesn't get glued together).
      this.classifyFields(cells, sourceName, ctx);
      return;
    }
    if (header.rangeStartIdx !== null && header.rangeEndIdx !== null) {
      const a = cells[header.rangeStartIdx];
      const b = cells[header.rangeEndIdx];
      if (a && b) {
        const rangeToken = this.classifyIpRangePair(a, b);
        if (rangeToken) this.recordToken(rangeToken, sourceName, ctx);
      }
    }
    header.headerMap.forEach((hint, idx) => {
      const cell = cells[idx];
      if (!cell) return;
      const parsed = this.classifyToken(cell, sourceName, hint);
      this.recordToken(parsed, sourceName, ctx);
    });
  }

  private async parseDelimitedFile(filePath: string, delimiter: string, sourceName: string, ctx: FileParseContext): Promise<void> {
    let isFirstLine = true;
    let header: DelimitedHeader = { headerMap: new Map(), rangeStartIdx: null, rangeEndIdx: null, hasHeader: false };
    await this.forEachLine(filePath, (rawLine) => {
      const line = rawLine.trim();
      if (!line) return;
      if (isFirstLine) {
        isFirstLine = false;
        header = this.detectDelimitedHeader(line, delimiter);
        if (header.hasHeader) return; // header row consumed, not data
      }
      this.processDelimitedRow(line, delimiter, sourceName, header, ctx);
    });
  }

  private parseDelimitedContent(content: string, delimiter: string, sourceName: string, ctx: FileParseContext): void {
    const lines = content.split(/\r?\n/).filter((l) => l.trim().length > 0);
    if (lines.length === 0) return;
    const header = this.detectDelimitedHeader(lines[0], delimiter);
    const dataLines = header.hasHeader ? lines.slice(1) : lines;
    for (const line of dataLines) this.processDelimitedRow(line, delimiter, sourceName, header, ctx);
  }

  // Shared "unheadered row" classifier - used for both un-headered CSV/TSV
  // rows and whitespace-split multi-field line-list lines. Looks for an
  // adjacent IPv4 start/end pair first (recorded as one range), then a
  // decimal-integer boundary pair (IP2Location-style ip_from/ip_to columns
  // - recognized and *skipped*, not misread as two ASNs or two IPs), then
  // classifies every remaining, unconsumed cell individually.
  private classifyFields(cells: string[], sourceName: string, ctx: FileParseContext): void {
    const consumed = new Set<number>();
    let i = 0;
    while (i < cells.length - 1) {
      const a = cells[i];
      const b = cells[i + 1];
      const rangeToken = this.classifyIpRangePair(a, b);
      if (rangeToken) {
        this.recordToken(rangeToken, sourceName, ctx);
        consumed.add(i);
        consumed.add(i + 1);
        i += 2;
        continue;
      }
      if (this.looksLikeDecimalIpBoundary(a) && this.looksLikeDecimalIpBoundary(b) && parseInt(a, 10) <= parseInt(b, 10)) {
        consumed.add(i);
        consumed.add(i + 1);
        i += 2;
        continue;
      }
      i++;
    }
    for (let j = 0; j < cells.length; j++) {
      if (consumed.has(j)) continue;
      const parsed = this.classifyToken(cells[j], sourceName, null);
      this.recordToken(parsed, sourceName, ctx);
    }
  }

  // --- JSON --------------------------------------------------------------

  private async parseJsonFile(filePath: string, sourceName: string, size: number, ctx: FileParseContext): Promise<void> {
    if (size > LARGE_JSON_THRESHOLD_BYTES) {
      await this.parseNdjsonFile(filePath, sourceName, ctx);
      return;
    }
    this.parseJsonContent(fs.readFileSync(filePath, 'utf-8'), sourceName, ctx);
  }

  private async parseNdjsonFile(filePath: string, sourceName: string, ctx: FileParseContext): Promise<void> {
    let lineErrors = 0;
    await this.forEachLine(filePath, (rawLine) => {
      const line = rawLine.trim();
      if (!line) return;
      let obj: any;
      try {
        obj = JSON.parse(line);
      } catch {
        lineErrors++;
        return;
      }
      this.walkJson(obj, sourceName, null, ctx);
    });
    if (lineErrors > 0) {
      this.stats.errors += lineErrors;
      this.logger.warn(`DatasetLoader: ${sourceName} - ${lineErrors} NDJSON line(s) failed to parse`);
    }
  }

  private parseJsonContent(content: string, sourceName: string, ctx: FileParseContext): void {
    let data: any;
    try {
      data = JSON.parse(content);
    } catch {
      this.stats.errors++;
      this.logger.warn(`DatasetLoader: invalid JSON in ${sourceName}`);
      return;
    }
    this.walkJson(data, sourceName, null, ctx);
  }

  private walkJson(node: any, sourceName: string, parentHint: ColumnHint | null, ctx: FileParseContext): void {
    if (node === null || node === undefined) return;
    if (typeof node === 'string') {
      const parsed = this.classifyToken(node, sourceName, parentHint);
      this.recordToken(parsed, sourceName, ctx);
      return;
    }
    if (typeof node === 'number') {
      if (parentHint === 'asn' && Number.isFinite(node)) this.recordToken({ kind: 'asn', value: node }, sourceName, ctx);
      return;
    }
    if (Array.isArray(node)) {
      for (const item of node) this.walkJson(item, sourceName, parentHint, ctx);
      return;
    }
    if (typeof node === 'object') {
      // A dict keyed by IP/CIDR (e.g. {"1.2.3.0/24": "reason"}) - classify
      // the key itself whenever it looks like IP/CIDR/ASN data.
      for (const [key, value] of Object.entries(node)) {
        const ipLike = this.classifyIpLike(key);
        if (ipLike) this.recordToken(ipLike, sourceName, ctx);
        else {
          const asn = this.parseAsnToken(key);
          if (asn !== null) this.recordToken({ kind: 'asn', value: asn }, sourceName, ctx);
        }
        const hintKey = key.toLowerCase().replace(/[^a-z0-9_]/g, '');
        const hint = COLUMN_HINTS[hintKey] || null;
        this.walkJson(value, sourceName, hint, ctx);
      }
    }
  }

  // --- Optional formats (lazy-required, fail-open) -----------------------

  private async parseMmdbFile(filePath: string, sourceName: string): Promise<void> {
    await this.parseMmdbBuffer(fs.readFileSync(filePath), sourceName);
  }

  private async parseMmdbBuffer(buffer: Buffer, sourceName: string): Promise<void> {
    let maxmind: any;
    try {
      maxmind = require('maxmind');
    } catch {
      this.logger.warn(`DatasetLoader: found ${sourceName} but the optional "maxmind" package isn't installed - run "npm install maxmind" to enable .mmdb datasets`);
      this.stats.skipped++;
      return;
    }
    try {
      const reader = new maxmind.Reader(buffer);
      this.mmdbReaders.push({ name: sourceName, reader });
      this.logger.info(`DatasetLoader: registered MMDB dataset ${sourceName} (queried live per connection)`);
    } catch (e) {
      this.stats.errors++;
      this.logger.warn(`DatasetLoader: failed to open MMDB ${sourceName}: ${(e as Error).message}`);
    }
  }

  private async parseParquetFile(filePath: string, sourceName: string, ctx: FileParseContext): Promise<void> {
    let parquet: any;
    try {
      parquet = require('parquetjs-lite');
    } catch {
      this.logger.warn(`DatasetLoader: found ${sourceName} but the optional "parquetjs-lite" package isn't installed - run "npm install parquetjs-lite" to enable .parquet datasets`);
      this.stats.skipped++;
      return;
    }
    let reader: any;
    try {
      reader = await parquet.ParquetReader.openFile(filePath);
      const cursor = reader.getCursor();
      let record: any = await cursor.next();
      while (record) {
        this.recordParquetRow(record, sourceName, ctx);
        record = await cursor.next();
      }
    } catch (e) {
      this.stats.errors++;
      this.logger.warn(`DatasetLoader: failed to read parquet file ${sourceName}: ${(e as Error).message}`);
    } finally {
      if (reader) { try { await reader.close(); } catch { /* ignore */ } }
    }
  }

  private async parseParquetBuffer(buffer: Buffer, sourceName: string, ctx: FileParseContext): Promise<void> {
    // parquetjs-lite needs real random file access, so a zip-extracted
    // buffer is spilled to a short-lived temp file rather than skipped
    // outright - deleted immediately after reading either way.
    const tmpPath = path.join(os.tmpdir(), `antivpn-dataset-${Date.now()}-${Math.random().toString(36).slice(2)}.parquet`);
    try {
      fs.writeFileSync(tmpPath, buffer);
      await this.parseParquetFile(tmpPath, sourceName, ctx);
    } finally {
      fs.unlink(tmpPath, () => { /* best-effort cleanup */ });
    }
  }

  private recordParquetRow(record: Record<string, any>, sourceName: string, ctx: FileParseContext): void {
    // Same start_ip/end_ip range-pair recognition CSV headers get, since
    // several of the sample parquet exports mirror their CSV counterpart's
    // column layout exactly.
    let rangeStartKey: string | null = null;
    let rangeEndKey: string | null = null;
    for (const key of Object.keys(record)) {
      const hintKey = key.toLowerCase().replace(/[^a-z0-9_]/g, '');
      if (RANGE_START_COLUMNS.has(hintKey)) rangeStartKey = key;
      else if (RANGE_END_COLUMNS.has(hintKey)) rangeEndKey = key;
    }
    if (rangeStartKey && rangeEndKey) {
      const a = record[rangeStartKey];
      const b = record[rangeEndKey];
      if (a !== null && a !== undefined && b !== null && b !== undefined) {
        const rangeToken = this.classifyIpRangePair(String(a), String(b));
        if (rangeToken) this.recordToken(rangeToken, sourceName, ctx);
      }
    }
    for (const [key, value] of Object.entries(record)) {
      if (value === null || value === undefined) continue;
      if (key === rangeStartKey || key === rangeEndKey) continue;
      const hintKey = key.toLowerCase().replace(/[^a-z0-9_]/g, '');
      const hint = COLUMN_HINTS[hintKey];
      if (!hint) continue;
      const strValue = typeof value === 'object' && value?.toString ? value.toString() : String(value);
      const parsed = this.classifyToken(strValue, sourceName, hint);
      this.recordToken(parsed, sourceName, ctx);
    }
  }

  // ========================================================================
  // TOKEN CLASSIFICATION + DEDUPLICATION
  // ========================================================================

  private classifyToken(rawToken: string, sourceName: string, columnHint: ColumnHint | null): ParsedToken {
    const token = (rawToken || '').trim().replace(/^["']|["']$/g, '');
    if (!token) return null;

    if (columnHint === 'asn') {
      const n = this.parseAsnNumber(token);
      return n !== null ? { kind: 'asn', value: n } : null;
    }
    if (columnHint === 'ip' || columnHint === 'cidr') {
      return this.classifyIpLike(token);
    }

    // No column/context hint - generic per-token heuristic (plain line
    // lists, unstructured JSON string arrays, un-headered CSV cells).
    const ipLike = this.classifyIpLike(token);
    if (ipLike) return ipLike;

    const asn = this.parseAsnToken(token);
    if (asn !== null) return { kind: 'asn', value: asn };

    // A bare number is only treated as an ASN if the filename itself says
    // so (e.g. "asn_ovh.txt") - otherwise a plain numeric line is too
    // ambiguous to guess at.
    if (/^\d{1,10}$/.test(token) && /asn/i.test(sourceName)) {
      return { kind: 'asn', value: parseInt(token, 10) };
    }

    return null;
  }

  private classifyIpLike(token: string): ParsedToken {
    const direct = this.classifyIpLikeDirect(token);
    if (direct) return direct;
    // Not a bare IP/CIDR - try again with a leading URL scheme (and
    // optional userinfo) and a trailing :port stripped off, so proxy
    // lists in "scheme://ip:port" or "ip:port" form still classify.
    const stripped = this.stripSchemeAndPort(token);
    return stripped !== token ? this.classifyIpLikeDirect(stripped) : null;
  }

  private classifyIpLikeDirect(token: string): ParsedToken {
    if (IPV4_CIDR_RE.test(token)) return { kind: 'cidr', value: token, isV6: false };
    if (IPV4_RE.test(token)) return { kind: 'ip', value: token, isV6: false };
    if (token.includes(':')) {
      const [addr, prefix] = token.split('/');
      if (this.looksLikeIpv6(addr)) {
        return prefix !== undefined
          ? { kind: 'cidr', value: `${addr.toLowerCase()}/${prefix}`, isV6: true }
          : { kind: 'ip', value: addr.toLowerCase(), isV6: true };
      }
    }
    return null;
  }

  private stripSchemeAndPort(token: string): string {
    let t = token;
    const schemeMatch = t.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//);
    if (schemeMatch) t = t.slice(schemeMatch[0].length);
    const bracketMatch = t.match(/^\[([0-9a-fA-F:]+)\](?::\d+)?$/);
    if (bracketMatch) return bracketMatch[1];
    const atIdx = t.lastIndexOf('@');
    if (atIdx !== -1) t = t.slice(atIdx + 1);
    const ipv4PortMatch = t.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+$/);
    if (ipv4PortMatch) return ipv4PortMatch[1];
    return t;
  }

  // Both dotted-quad IPv4, ascending - a genuine IP range (CSV/parquet
  // start_ip/end_ip columns, or a "1.2.3.0 1.2.3.255" line-list pair).
  private classifyIpRangePair(a: string, b: string): ParsedToken {
    if (!IPV4_RE.test(a) || !IPV4_RE.test(b)) return null;
    const startNum = this.ipv4ToNumber(a);
    const endNum = this.ipv4ToNumber(b);
    if (startNum === null || endNum === null || startNum > endNum) return null;
    return { kind: 'range', startNum, endNum };
  }

  // A bare decimal integer in valid 32-bit IPv4-as-integer range (e.g.
  // IP2Location's ip_from/ip_to columns) - recognized so it can be
  // deliberately skipped instead of misread as an ASN or two unrelated
  // numbers by the generic per-cell fallback.
  private looksLikeDecimalIpBoundary(token: string): boolean {
    if (!/^\d{1,10}$/.test(token)) return false;
    const n = parseInt(token, 10);
    return Number.isFinite(n) && n >= 0 && n <= 0xFFFFFFFF;
  }

  private parseAsnToken(token: string): number | null {
    const m = token.trim().match(/^ASN?\s*[:#]?\s*(\d{1,10})$/i);
    return m ? parseInt(m[1], 10) : null;
  }

  private parseAsnNumber(token: string): number | null {
    const asn = this.parseAsnToken(token);
    if (asn !== null) return asn;
    const trimmed = token.trim();
    const n = parseInt(trimmed, 10);
    return /^\d{1,10}$/.test(trimmed) && Number.isFinite(n) ? n : null;
  }

  private recordToken(parsed: ParsedToken, sourceName: string, ctx: FileParseContext): void {
    if (!parsed) return;
    const result = this.addEntry(parsed, sourceName, ctx);
    if (result === 'added') this.stats.added++;
    else if (result === 'duplicate') this.stats.duplicates++;
    else this.stats.skipped++;
  }

  // Every add path here is where the requirement "if this is a duplicate
  // then ignore this asn/ip" is enforced - scoped to the current file's
  // context (ctx), since each file's contribution is now persisted
  // independently (see persistContext) rather than one global buffer
  // spanning the whole datasets directory.
  //
  // IPv4 ip/cidr/range entries are NOT deduplicated here (deliberately -
  // see below); IPv6 and ASN entries still are, via pendingExactKeys/
  // pendingAsn, since their volume is orders of magnitude smaller.
  //
  // WHY NOT DEDUPE IPv4: a per-file `Set<string>` of dedup keys was
  // measured directly against this project's own data/datasets corpus to
  // cost roughly 200 bytes per entry - for a single real-world netset file
  // with 2.5M lines, that's ~500MB in ONE Set, and with several such files
  // parsing concurrently (see the 8-way file concurrency), multi-GB. A
  // literal duplicate CIDR within one file (or across different files/
  // sources) is functionally harmless either way: RangeTable.
  // fromSortedPairs (built from RangeIndexStore at query time) already
  // merges overlapping/identical ranges regardless of how many DB rows
  // produced them, so skipping the check changes nothing about what
  // matches at runtime - it only means an already-redundant DB row gets
  // written instead of skipped, which costs a few bytes on disk, not
  // gigabytes in RAM. getStats().duplicates_skipped now reflects only
  // ASN dedup as a result.
  private addEntry(token: ParsedToken, sourceName: string, ctx: FileParseContext): 'added' | 'duplicate' | 'skipped' {
    if (!token) return 'skipped';

    if (token.kind === 'ip' || token.kind === 'cidr') {
      if (token.isV6) {
        const key = `6:${token.kind}:${token.value.toLowerCase()}`;
        if (ctx.pendingExactKeys.has(key)) return 'duplicate';
        ctx.pendingExactKeys.add(key);
        ctx.pendingIpv6.push({ kind: token.kind === 'ip' ? 'ip' : 'cidr', value: token.value.toLowerCase() });
      } else {
        // Streamed straight to the DB session instead of buffered into a
        // whole-file array - see FileParseContext's doc comment.
        const range = token.kind === 'ip' ? this.singleIpRange(token.value) : this.cidrToRange(token.value);
        if (!range) return 'skipped';
        if (!this.acceptIpv4Range(range[0], range[1], sourceName, ctx)) return 'skipped';
        ctx.rangeSession.addRange(range[0], range[1]);
      }
      return 'added';
    }

    if (token.kind === 'range') {
      if (!this.acceptIpv4Range(token.startNum, token.endNum, sourceName, ctx)) return 'skipped';
      ctx.rangeSession.addRange(token.startNum, token.endNum);
      return 'added';
    }

    if (token.kind === 'asn') {
      // AS0 is IANA-reserved ("not routed" per RFC 7607) - never a real
      // network, even if a dataset lists it explicitly.
      if (token.value === 0) return 'skipped';
      // Already covered by the project's own curated hosting/VPN ASN list
      // - no point tracking it twice.
      if (VERIFIED_HOSTING_VPN_ASNS_SET.has(token.value)) return 'duplicate';
      if (ctx.pendingAsn.has(token.value)) return 'duplicate';
      ctx.pendingAsn.set(token.value, sourceName);
      return 'added';
    }

    return 'skipped';
  }

  // FP-hardening load-time sanity guards for IPv4 dataset entries. Rejects
  // (with a warning log) entries that can only ever produce false positives:
  //   - private/reserved/loopback/link-local/multicast ranges (a dataset
  //     listing 10.0.0.0/8 or 127.0.0.1 is describing infrastructure, not
  //     abusive public IPs - and Layer 0's isPrivateIP no longer being the
  //     only line of defense matters in 'instant' mode);
  //   - ranges broader than a /8 (16.7M+ addresses in one line) - no real
  //     abuse list legitimately bans a /7; that's a geo/reference database
  //     row or a parse artifact.
  // Also accumulates per-file coverage so persistContext can warn when one
  // file blankets an implausible share of the address space. Detection is
  // not reduced: no legitimate VPN/proxy list entry is private space or
  // wider than /8 (the widest real-world hosting allocations are /9-/10,
  // and those are still accepted).
  private static readonly RESERVED_IPV4_RANGES: Array<[number, number]> = [
    [0x00000000, 0x00FFFFFF], // 0.0.0.0/8 "this network"
    [0x0A000000, 0x0AFFFFFF], // 10.0.0.0/8 private
    [0x64400000, 0x647FFFFF], // 100.64.0.0/10 CGNAT shared space
    [0x7F000000, 0x7FFFFFFF], // 127.0.0.0/8 loopback
    [0xA9FE0000, 0xA9FEFFFF], // 169.254.0.0/16 link-local
    [0xAC100000, 0xAC1FFFFF], // 172.16.0.0/12 private
    [0xC0A80000, 0xC0A8FFFF], // 192.168.0.0/16 private
    [0xE0000000, 0xFFFFFFFF], // 224.0.0.0/3 multicast + reserved + broadcast
  ];
  private static readonly MAX_RANGE_SPAN = 0x1000000; // /8 = 16,777,216 addresses

  private acceptIpv4Range(start: number, end: number, sourceName: string, ctx: FileParseContext): boolean {
    const span = end - start + 1;
    if (span > DatasetLoader.MAX_RANGE_SPAN) {
      this.logger.warn(`DatasetLoader: rejecting ${sourceName} entry ${this.numberToIp(start)}-${this.numberToIp(end)} (${(span / 1e6).toFixed(1)}M addresses - wider than a /8; abuse lists don't ban that much space, reference/geo databases do)`);
      return false;
    }
    for (const [rs, re] of DatasetLoader.RESERVED_IPV4_RANGES) {
      if (start <= re && end >= rs) {
        this.logger.warn(`DatasetLoader: rejecting ${sourceName} entry ${this.numberToIp(start)}-${this.numberToIp(end)} (overlaps private/reserved space)`);
        return false;
      }
    }
    ctx.addressCount += span;
    return true;
  }

  // ========================================================================
  // IP/CIDR MATH HELPERS (self-contained - deliberately not shared with
  // ListManager/NetworkReputationStore's private equivalents to keep this
  // file independently testable and avoid coupling singletons together)
  // ========================================================================

  private ipv4ToNumber(ip: string): number | null {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return null;
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  }

  private numberToIp(num: number): string {
    return [(num >>> 24) & 255, (num >>> 16) & 255, (num >>> 8) & 255, num & 255].join('.');
  }

  private cidrToRange(cidr: string): [number, number] | null {
    const [range, bitsStr] = cidr.split('/');
    const bits = parseInt(bitsStr, 10);
    if (isNaN(bits) || bits < 0 || bits > 32) return null;
    const base = this.ipv4ToNumber(range);
    if (base === null) return null;
    // Mask host bits off so a misaligned CIDR (e.g. 1.2.3.128/24) still
    // yields its true network range (1.2.3.0 - 1.2.3.255) instead of a
    // shifted one - an unmasked base produces both false negatives (real
    // IPs in the network don't match) and false positives (IPs outside it
    // do), and for a high block could even wrap into an inverted range that
    // corrupts the packed-range binary search.
    const mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
    const start = (base & mask) >>> 0;
    const size = bits === 0 ? 0x100000000 : Math.pow(2, 32 - bits);
    const end = (start + size - 1) >>> 0;
    return [start, end];
  }

  private singleIpRange(ip: string): [number, number] | null {
    const n = this.ipv4ToNumber(ip);
    return n === null ? null : [n, n];
  }

  private looksLikeIpv6(addr: string): boolean {
    return this.expandIpv6(addr) !== null;
  }

  private expandIpv6(ip: string): string[] | null {
    const clean = ip.split('%')[0];
    if (!clean.includes(':')) return null;
    if (!/^[0-9a-fA-F:]+$/.test(clean)) return null;
    const parts = clean.split('::');
    if (parts.length > 2) return null;
    const head = parts[0] ? parts[0].split(':').filter(Boolean) : [];
    const tail = parts.length === 2 && parts[1] ? parts[1].split(':').filter(Boolean) : [];
    if (parts.length === 1) {
      const groups = clean.split(':');
      if (groups.length !== 8) return null;
      return groups.map((g) => g.padStart(4, '0'));
    }
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    return [...head, ...new Array(missing).fill('0000'), ...tail].map((g) => g.padStart(4, '0'));
  }

  private ipv6ToBigInt(ip: string): bigint | null {
    const groups = this.expandIpv6(ip);
    if (!groups) return null;
    let result = 0n;
    for (const g of groups) result = (result << 16n) | BigInt(parseInt(g, 16));
    return result;
  }

  private ipv6InCidr(ip: string, cidr: string): boolean {
    const [range, bitsStr] = cidr.split('/');
    const bits = parseInt(bitsStr, 10);
    if (isNaN(bits) || bits < 0 || bits > 128) return false;
    const ipNum = this.ipv6ToBigInt(ip);
    const rangeNum = this.ipv6ToBigInt(range);
    if (ipNum === null || rangeNum === null) return false;
    const shift = BigInt(128 - bits);
    return (ipNum >> shift) === (rangeNum >> shift);
  }

  // --- Text sniffing for extension-less/unrecognized files ---------------
  private looksLikeTextBuffer(buffer: Buffer): boolean {
    const sample = buffer.subarray(0, Math.min(512, buffer.length));
    if (sample.length === 0) return true;
    let nonPrintable = 0;
    for (const byte of sample) {
      if (byte === 0) return false; // NUL byte - almost certainly binary
      if (byte < 9 || (byte > 13 && byte < 32)) nonPrintable++;
    }
    return nonPrintable / sample.length < 0.1;
  }

  private looksLikeText(filePath: string): boolean {
    try {
      const fd = fs.openSync(filePath, 'r');
      const buf = Buffer.alloc(512);
      const bytesRead = fs.readSync(fd, buf, 0, 512, 0);
      fs.closeSync(fd);
      return this.looksLikeTextBuffer(buf.subarray(0, bytesRead));
    } catch {
      return false;
    }
  }
}
