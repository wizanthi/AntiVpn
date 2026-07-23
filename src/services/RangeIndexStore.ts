// src/services/RangeIndexStore.ts
//
// Bulk IP-range/ASN import bookkeeping, dedicated and separate from
// StorageAdapter.ts (which serves small, whole-document operator stores -
// blacklist.json, whitelist.json, ...). Bulk range data needs real
// relational bookkeeping instead: per-source rows so a single changed
// source can be replaced without touching the rest (dedup/incremental/
// resume), and a table tracking which dataset files have already been
// imported so unchanged files are never re-parsed. That's what this file
// provides.
//
// BACKENDS: SQLite (via Node's built-in node:sqlite - Node >= 22.5) is the
// default and requires no configuration. If the operator sets
// storage.type = 'mysql' in config.json, this store persists into the same
// MySQL database StorageAdapter.ts uses instead - so an operator who wants
// everything in one database gets lists AND datasets there too, not just the
// small operator-managed stores. On MySQL every bad IPv4 range (curated
// lists, operator datasets, and the operator blacklist) lands in one
// `blacklist` table keyed by a `kind` column, operator whitelist IPs in a
// `whitelist` table, and the IP->ASN table in `antivpn_asns_table`; none
// collide with StorageAdapter's antivpn_store table. Falls back to SQLite
// (same fail-open pattern as StorageAdapter/createStorageAdapter) if the
// MySQL backend can't be initialized.
//
// WHY THE PUBLIC API IS FULLY ASYNC: SQLite (via node:sqlite) is
// synchronous under the hood, but MySQL (mysql2) is not - every read/write
// here is a real network round trip against that backend. Every public
// method below returns a Promise so both backends fit behind the same
// interface; the SQLite implementation just resolves immediately after
// doing its work synchronously.
//
// THE ONE EXCEPTION: RangeWriteSession.addRange() stays synchronous - it's
// called once per parsed line in DatasetLoader's streaming import loops
// (potentially millions of times per file), and awaiting a promise on
// every single call would both slow that hot loop down and, for MySQL,
// serialize each line behind a network round trip. It buffers into a
// local batch and flushes the batch (async, in the background) once it's
// full; only finish() - called once per file - is awaited by callers, and
// that awaits every flush the session ever kicked off, so no data is ever
// lost even though addRange() itself never blocks.
//
// RUNTIME HOT PATH: nothing in IpChecker/ListManager/DatasetLoader/AsnIndex
// queries this store per-connection. At startup (and after each background
// refresh), the relevant table is bulk-read once into packed typed arrays
// (see RangeTable.ts) - the DB is the source of truth and import engine,
// not a per-lookup query target.
import * as fs from 'fs';
import * as path from 'path';
import { Logger } from '../utils/Logger';
import { StorageConfig } from '../types';

export interface Ipv6Entry {
  kind: 'ip' | 'cidr';
  value: string;
}

export interface AsnTableRow {
  start: number;
  end: number;
  asn: number;
  name: string;
  // ISO-2 country code from iptoasn.com's bulk TSV (may be '' / 'NONE' for
  // unattributed ranges). Powers datasets.exclude_countries - see
  // DatasetsConfig - and nothing else; no detection layer treats a country
  // itself as a signal.
  country: string;
}

// Incremental writer for one source's ranges, handed to a caller that's
// streaming a file/response line by line (see DatasetLoader.newContext).
// See the file-level comment above for why addRange() itself is
// synchronous while finish() is awaited.
export interface RangeWriteSession {
  addRange(start: number, end: number): void;
  // Flushes any pending batch (awaiting every flush this session kicked
  // off, so the caller knows all of it has actually landed) and, if this
  // source ended up with zero ranges, still clears its previously-stored
  // rows (replace-with-empty semantics - a source that used to contribute
  // entries but no longer does shouldn't leave stale rows behind).
  finish(): Promise<void>;
}

// The backend-agnostic surface RangeIndexStore delegates to. Both
// SqliteRangeBackend and MysqlRangeBackend implement this identically from
// every caller's point of view - see the file-level comment for why it's
// fully async.
interface RangeBackend {
  replaceListRangesForSource(source: string, ranges: Array<[number, number]>): Promise<void>;
  loadListRangesUnion(): Promise<{ starts: Uint32Array; ends: Uint32Array }>;

  replaceDatasetRangesForSource(source: string, ranges: Array<[number, number]>): Promise<void>;
  beginDatasetRangeSession(source: string): Promise<RangeWriteSession>;
  loadDatasetRangesUnion(): Promise<{ starts: Uint32Array; ends: Uint32Array }>;

  replaceDatasetIpv6ForSource(source: string, entries: Ipv6Entry[]): Promise<void>;
  loadDatasetIpv6Union(): Promise<Ipv6Entry[]>;

  replaceDatasetAsnForFile(fileKey: string, entries: Array<{ asn: number; label: string }>): Promise<void>;
  loadDatasetAsnUnion(): Promise<Map<number, string>>;

  replaceAsnTable(rows: AsnTableRow[]): Promise<void>;
  loadAsnTable(): Promise<AsnTableRow[]>;

  // Mirror of ListManager's small operator-managed blacklist/whitelist IPs
  // into the same unified blacklist/whitelist tables the bulk list/dataset
  // ranges live in (MySQL only - see MysqlRangeBackend). On the SQLite/file
  // backends these are no-ops: the operator lists already persist as JSON
  // documents through StorageAdapter there, and this consolidation is
  // specifically a "everything in one MySQL database, in blacklist/whitelist
  // tables" request.
  replaceOperatorBlacklist(ranges: Array<[number, number]>): Promise<void>;
  replaceOperatorWhitelist(ranges: Array<[number, number]>): Promise<void>;

  isFileUnchanged(filePath: string, size: number, mtimeMs: number): Promise<boolean>;
  markFileImported(filePath: string, size: number, mtimeMs: number): Promise<void>;

  getSourceCacheHash(name: string): Promise<{ hash: string; ipCount: number } | null>;
  setSourceCacheHash(name: string, hash: string, ipCount: number): Promise<void>;
  // Bulk variant of getSourceCacheHash - one round trip for every source's
  // cache row instead of one round trip per source. ListUpdater uses this
  // once at startup to mirror the whole table into memory (it's the sole
  // writer of these rows, so an in-memory mirror kept in sync with its own
  // writes stays correct) instead of paying a network round trip per
  // source on every single update cycle.
  getAllSourceCacheHashes(): Promise<Map<string, { hash: string; ipCount: number }>>;

  close(): Promise<void>;
}

// ============================================================================
// SQLITE (default) - Node's built-in node:sqlite (DatabaseSync).
// ============================================================================
class SqliteRangeBackend implements RangeBackend {
  private logger: Logger;
  private db: any;

  private listRanges!: SqliteSourceRangeTable;
  private datasetRanges!: SqliteSourceRangeTable;
  private sourceInterner!: SqliteSourceInterner;
  private stmts: Record<string, any> = {};

  constructor() {
    this.logger = Logger.getInstance();
  }

  async init(dbPath: string): Promise<void> {
    const { DatabaseSync } = require('node:sqlite');
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    this.db = new DatabaseSync(dbPath);
    this.db.exec('PRAGMA journal_mode = WAL');
    this.db.exec('PRAGMA synchronous = NORMAL');
    // Memory-mapped I/O is SQLite's default in some builds and, for a
    // multi-hundred-MB-to-multi-GB bulk-import database, maps a
    // proportional fraction of the file into this process's address space
    // - counted as resident memory (RSS) by the OS even though it's really
    // reclaimable page cache. Measured directly: a 10M-row bulk insert held
    // ~2.9GB RSS with the default mmap behavior versus ~45MB with it
    // disabled, for the exact same on-disk data. Explicitly off, since
    // this project's whole point is running comfortably in a bounded
    // (512MB-1GB) memory budget - regular buffered I/O is still fast
    // enough for this store's access pattern (a handful of large
    // sequential scans at startup/refresh, not per-connection lookups).
    this.db.exec('PRAGMA mmap_size = 0');
    this.db.exec(`
      -- Interned source paths/names shared by list_ranges and
      -- dataset_ranges - real datasets can contribute millions of rows
      -- each, so a 4-byte integer foreign key beats repeating a 60-80
      -- byte path string on every one of those rows.
      CREATE TABLE IF NOT EXISTS sources (
        id INTEGER PRIMARY KEY,
        path TEXT NOT NULL UNIQUE
      );

      CREATE TABLE IF NOT EXISTS list_ranges (
        source_id INTEGER NOT NULL,
        start_ip INTEGER NOT NULL,
        end_ip INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_list_ranges_source ON list_ranges(source_id);
      -- Covering (start_ip, end_ip): the startup union scan selects start_ip
      -- and end_ip ordered by start_ip, so including end_ip turns it into an
      -- index-only scan (no per-row table lookup, no sort).
      CREATE INDEX IF NOT EXISTS idx_list_ranges_start_cov ON list_ranges(start_ip, end_ip);

      CREATE TABLE IF NOT EXISTS dataset_ranges (
        source_id INTEGER NOT NULL,
        start_ip INTEGER NOT NULL,
        end_ip INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_dataset_ranges_source ON dataset_ranges(source_id);
      CREATE INDEX IF NOT EXISTS idx_dataset_ranges_start_cov ON dataset_ranges(start_ip, end_ip);

      CREATE TABLE IF NOT EXISTS dataset_ipv6 (
        source_id INTEGER NOT NULL,
        kind TEXT NOT NULL,
        value TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_dataset_ipv6_source ON dataset_ipv6(source_id);

      -- file_key: the outer dataset file this row came from - used for
      -- incremental replace-by-file (delete-then-reinsert on reparse).
      -- label: the human-readable attribution surfaced by
      -- DatasetLoader.isAsnMatch() (e.g. "asn_ovh.txt", or
      -- "bundle.zip::inner/asn_ovh.txt") - distinct from file_key since a
      -- zip's many inner entries all share one file_key (the zip itself)
      -- but each keeps its own label. Not interned - ASN row counts are
      -- orders of magnitude smaller than range counts (hundreds, not
      -- millions), so the repeated-string cost here is negligible.
      CREATE TABLE IF NOT EXISTS dataset_asn (
        file_key TEXT NOT NULL,
        label TEXT NOT NULL,
        asn INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_dataset_asn_file_key ON dataset_asn(file_key);

      CREATE TABLE IF NOT EXISTS asn_table (
        start_ip INTEGER NOT NULL,
        end_ip INTEGER NOT NULL,
        asn INTEGER NOT NULL,
        name TEXT NOT NULL,
        country TEXT NOT NULL DEFAULT ''
      );
      CREATE INDEX IF NOT EXISTS idx_asn_table_start_cov ON asn_table(start_ip, end_ip, asn, name);

      CREATE TABLE IF NOT EXISTS list_source_cache (
        name TEXT PRIMARY KEY,
        hash TEXT NOT NULL,
        ip_count INTEGER NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS import_file_state (
        path TEXT PRIMARY KEY,
        size INTEGER NOT NULL,
        mtime_ms INTEGER NOT NULL,
        imported_at TEXT NOT NULL
      );
    `);

    this.sourceInterner = new SqliteSourceInterner(
      this.db.prepare('SELECT id FROM sources WHERE path = ?'),
      this.db.prepare('INSERT INTO sources (path) VALUES (?)'),
    );

    // One-shot migration for databases created before the country column
    // existed (CREATE TABLE IF NOT EXISTS above never alters an existing
    // table). Throws "duplicate column name" once it's there - ignored.
    try { this.db.exec("ALTER TABLE asn_table ADD COLUMN country TEXT NOT NULL DEFAULT ''"); } catch { /* column already exists */ }

    this.listRanges = new SqliteSourceRangeTable(
      this.db,
      this.sourceInterner,
      this.db.prepare('DELETE FROM list_ranges WHERE source_id = ?'),
      this.db.prepare('INSERT INTO list_ranges (source_id, start_ip, end_ip) VALUES (?, ?, ?)'),
      this.db.prepare('SELECT start_ip, end_ip FROM list_ranges ORDER BY start_ip'),
      this.db.prepare('SELECT COUNT(*) as c FROM list_ranges'),
    );
    this.datasetRanges = new SqliteSourceRangeTable(
      this.db,
      this.sourceInterner,
      this.db.prepare('DELETE FROM dataset_ranges WHERE source_id = ?'),
      this.db.prepare('INSERT INTO dataset_ranges (source_id, start_ip, end_ip) VALUES (?, ?, ?)'),
      this.db.prepare('SELECT start_ip, end_ip FROM dataset_ranges ORDER BY start_ip'),
      this.db.prepare('SELECT COUNT(*) as c FROM dataset_ranges'),
    );

    this.stmts = {
      deleteIpv6BySource: this.db.prepare('DELETE FROM dataset_ipv6 WHERE source_id = ?'),
      insertIpv6: this.db.prepare('INSERT INTO dataset_ipv6 (source_id, kind, value) VALUES (?, ?, ?)'),
      selectAllIpv6: this.db.prepare('SELECT kind, value FROM dataset_ipv6'),

      deleteAsnByFileKey: this.db.prepare('DELETE FROM dataset_asn WHERE file_key = ?'),
      insertAsn: this.db.prepare('INSERT INTO dataset_asn (file_key, label, asn) VALUES (?, ?, ?)'),
      selectAllAsn: this.db.prepare('SELECT label, asn FROM dataset_asn'),

      deleteAsnTable: this.db.prepare('DELETE FROM asn_table'),
      insertAsnTable: this.db.prepare('INSERT INTO asn_table (start_ip, end_ip, asn, name, country) VALUES (?, ?, ?, ?, ?)'),
      selectAsnTable: this.db.prepare('SELECT start_ip as start, end_ip as end, asn, name, country FROM asn_table ORDER BY start_ip'),

      selectFileState: this.db.prepare('SELECT size, mtime_ms as mtimeMs FROM import_file_state WHERE path = ?'),
      upsertFileState: this.db.prepare(
        'INSERT INTO import_file_state (path, size, mtime_ms, imported_at) VALUES (?, ?, ?, ?) ' +
        'ON CONFLICT(path) DO UPDATE SET size = excluded.size, mtime_ms = excluded.mtime_ms, imported_at = excluded.imported_at'
      ),

      selectSourceCache: this.db.prepare('SELECT hash, ip_count as ipCount FROM list_source_cache WHERE name = ?'),
      selectAllSourceCache: this.db.prepare('SELECT name, hash, ip_count as ipCount FROM list_source_cache'),
      upsertSourceCache: this.db.prepare(
        'INSERT INTO list_source_cache (name, hash, ip_count, updated_at) VALUES (?, ?, ?, ?) ' +
        'ON CONFLICT(name) DO UPDATE SET hash = excluded.hash, ip_count = excluded.ip_count, updated_at = excluded.updated_at'
      ),
    };

    this.logger.info(`RangeIndexStore: using SQLite (${dbPath})`);
  }

  async replaceListRangesForSource(source: string, ranges: Array<[number, number]>): Promise<void> {
    this.listRanges.replaceForSource(source, ranges);
  }

  async loadListRangesUnion(): Promise<{ starts: Uint32Array; ends: Uint32Array }> {
    return this.listRanges.loadAll();
  }

  async replaceDatasetRangesForSource(source: string, ranges: Array<[number, number]>): Promise<void> {
    this.datasetRanges.replaceForSource(source, ranges);
  }

  async beginDatasetRangeSession(source: string): Promise<RangeWriteSession> {
    return this.datasetRanges.beginSession(source);
  }

  async loadDatasetRangesUnion(): Promise<{ starts: Uint32Array; ends: Uint32Array }> {
    return this.datasetRanges.loadAll();
  }

  async replaceDatasetIpv6ForSource(source: string, entries: Ipv6Entry[]): Promise<void> {
    const sourceId = this.sourceInterner.getOrCreateId(source);
    this.db.exec('BEGIN');
    try {
      this.stmts.deleteIpv6BySource.run(sourceId);
      for (const e of entries) this.stmts.insertIpv6.run(sourceId, e.kind, e.value);
      this.db.exec('COMMIT');
    } catch (e) {
      this.db.exec('ROLLBACK');
      throw e;
    }
  }

  async loadDatasetIpv6Union(): Promise<Ipv6Entry[]> {
    return this.stmts.selectAllIpv6.all() as Ipv6Entry[];
  }

  async replaceDatasetAsnForFile(fileKey: string, entries: Array<{ asn: number; label: string }>): Promise<void> {
    this.db.exec('BEGIN');
    try {
      this.stmts.deleteAsnByFileKey.run(fileKey);
      for (const e of entries) this.stmts.insertAsn.run(fileKey, e.label, e.asn);
      this.db.exec('COMMIT');
    } catch (e) {
      this.db.exec('ROLLBACK');
      throw e;
    }
  }

  async loadDatasetAsnUnion(): Promise<Map<number, string>> {
    const rows = this.stmts.selectAllAsn.all() as Array<{ label: string; asn: number }>;
    const map = new Map<number, string>();
    for (const row of rows) if (!map.has(row.asn)) map.set(row.asn, row.label);
    return map;
  }

  async replaceAsnTable(rows: AsnTableRow[]): Promise<void> {
    this.db.exec('BEGIN');
    try {
      this.stmts.deleteAsnTable.run();
      for (const r of rows) this.stmts.insertAsnTable.run(r.start, r.end, r.asn, r.name, r.country || '');
      this.db.exec('COMMIT');
    } catch (e) {
      this.db.exec('ROLLBACK');
      throw e;
    }
  }

  async loadAsnTable(): Promise<AsnTableRow[]> {
    return this.stmts.selectAsnTable.all() as AsnTableRow[];
  }

  // No-op on SQLite/file: operator blacklist/whitelist already persist as
  // JSON documents via StorageAdapter here. The unified blacklist/whitelist
  // row tables are a MySQL-only consolidation (see MysqlRangeBackend).
  async replaceOperatorBlacklist(_ranges: Array<[number, number]>): Promise<void> { /* no-op */ }
  async replaceOperatorWhitelist(_ranges: Array<[number, number]>): Promise<void> { /* no-op */ }

  async isFileUnchanged(filePath: string, size: number, mtimeMs: number): Promise<boolean> {
    const row = this.stmts.selectFileState.get(filePath) as { size: number; mtimeMs: number } | undefined;
    return !!row && Number(row.size) === size && Number(row.mtimeMs) === mtimeMs;
  }

  async markFileImported(filePath: string, size: number, mtimeMs: number): Promise<void> {
    this.stmts.upsertFileState.run(filePath, size, mtimeMs, new Date().toISOString());
  }

  async getSourceCacheHash(name: string): Promise<{ hash: string; ipCount: number } | null> {
    const row = this.stmts.selectSourceCache.get(name) as { hash: string; ipCount: number } | undefined;
    return row ? { hash: row.hash, ipCount: Number(row.ipCount) } : null;
  }

  async setSourceCacheHash(name: string, hash: string, ipCount: number): Promise<void> {
    this.stmts.upsertSourceCache.run(name, hash, ipCount, new Date().toISOString());
  }

  async getAllSourceCacheHashes(): Promise<Map<string, { hash: string; ipCount: number }>> {
    const rows = this.stmts.selectAllSourceCache.all() as Array<{ name: string; hash: string; ipCount: number }>;
    const map = new Map<string, { hash: string; ipCount: number }>();
    for (const row of rows) map.set(row.name, { hash: row.hash, ipCount: Number(row.ipCount) });
    return map;
  }

  async close(): Promise<void> {
    if (this.db) this.db.close();
  }
}

// Interns a source path/name into a small integer id - see the SQLite
// schema comment above for why. Cached in-memory (per id/path pair,
// source count is at most a few thousand) since the same source is looked
// up repeatedly within one import pass.
class SqliteSourceInterner {
  private idByPath = new Map<string, number>();

  constructor(private selectStmt: any, private insertStmt: any) {}

  getOrCreateId(sourcePath: string): number {
    const cached = this.idByPath.get(sourcePath);
    if (cached !== undefined) return cached;
    const row = this.selectStmt.get(sourcePath) as { id: number } | undefined;
    if (row) {
      this.idByPath.set(sourcePath, row.id);
      return row.id;
    }
    const result = this.insertStmt.run(sourcePath);
    const id = Number(result.lastInsertRowid);
    this.idByPath.set(sourcePath, id);
    return id;
  }
}

// Shared "replace all rows for one source" primitive, backing both
// list_ranges (ListUpdater's curated sources) and dataset_ranges
// (DatasetLoader's operator datasets) - both follow the exact same
// dedup/incremental shape: delete this source's old rows, insert its
// current rows, all in one transaction so a crash mid-import can never
// leave a source half-written.
class SqliteSourceRangeTable {
  private static readonly BATCH_SIZE = 200_000;

  constructor(
    private db: any,
    private interner: SqliteSourceInterner,
    private deleteStmt: any,
    private insertStmt: any,
    private selectAllStmt: any,
    private countStmt: any,
  ) {}

  replaceForSource(source: string, ranges: Array<[number, number]>): void {
    const sourceId = this.interner.getOrCreateId(source);
    this.db.exec('BEGIN');
    try {
      this.deleteStmt.run(sourceId);
      for (const [start, end] of ranges) this.insertStmt.run(sourceId, start, end);
      this.db.exec('COMMIT');
    } catch (e) {
      this.db.exec('ROLLBACK');
      throw e;
    }
  }

  // See RangeWriteSession's doc comment above for why this exists. SQLite
  // is synchronous, so every flush here happens inline - finish() has
  // nothing left to await, but still returns a promise to satisfy the
  // shared RangeWriteSession interface both backends implement.
  beginSession(source: string): RangeWriteSession {
    const sourceId = this.interner.getOrCreateId(source);
    let deleted = false;
    let batchStarts: number[] = [];
    let batchEnds: number[] = [];

    const flush = (): void => {
      if (batchStarts.length === 0 && deleted) return; // nothing pending, already cleared
      this.db.exec('BEGIN');
      try {
        if (!deleted) { this.deleteStmt.run(sourceId); deleted = true; }
        for (let i = 0; i < batchStarts.length; i++) this.insertStmt.run(sourceId, batchStarts[i], batchEnds[i]);
        this.db.exec('COMMIT');
      } catch (e) {
        this.db.exec('ROLLBACK');
        throw e;
      }
      batchStarts = [];
      batchEnds = [];
    };

    return {
      addRange: (start: number, end: number): void => {
        batchStarts.push(start);
        batchEnds.push(end);
        if (batchStarts.length >= SqliteSourceRangeTable.BATCH_SIZE) flush();
      },
      finish: async (): Promise<void> => {
        flush();
      },
    };
  }

  // Bulk union across every source, ordered by start_ip - fed straight into
  // RangeTable.fromSortedPairs() by the caller. Uses iterate() (one row
  // object materialized at a time, immediately copied into the pre-sized
  // typed arrays and discarded) rather than all() - measured directly:
  // all() over this project's real data/datasets corpus (10M+ rows)
  // materializes every row as its own JS object simultaneously before
  // any of them can be converted, which alone accounted for multiple GB
  // of peak RSS. iterate() never holds more than one row object at a time.
  loadAll(): { starts: Uint32Array; ends: Uint32Array } {
    const n = Number((this.countStmt.get() as { c: number }).c);
    const starts = new Uint32Array(n);
    const ends = new Uint32Array(n);
    let i = 0;
    for (const row of this.selectAllStmt.iterate() as Iterable<{ start_ip: number; end_ip: number }>) {
      starts[i] = row.start_ip;
      ends[i] = row.end_ip;
      i++;
    }
    return { starts, ends };
  }
}

// ============================================================================
// MYSQL - used when config.json's storage.type = 'mysql', so an operator
// who's already pointed the small operator-managed stores at MySQL (see
// StorageAdapter.ts) gets lists/datasets/ASN data there too. Reuses the
// exact same connection config (StorageConfig['mysql']) and, therefore, the
// exact same database.
//
// TABLE LAYOUT (consolidated): every "bad" IPv4 range - curated list
// sources (ListUpdater), operator datasets (DatasetLoader) AND the small
// operator-managed blacklist (ListManager) - lives together in ONE
// `blacklist` table, distinguished by a `kind` column ('list' | 'dataset' |
// 'operator') so each origin can still be refreshed/loaded independently.
// Operator whitelist IPs live in a symmetric `whitelist` table. The offline
// IP->ASN table is `antivpn_asns_table`. Remaining bookkeeping (interned
// source paths, dataset IPv6 entries, dataset ASN attributions, list change-
// detection hashes, dataset file-import state) keeps its antivpn_* tables.
// None collide with StorageAdapter's antivpn_store table.
//
// Table/index sizing note: source paths, dataset file paths, and list
// source names are indexed VARCHAR(500) columns - comfortably inside
// InnoDB's 3072-byte (DYNAMIC row format) index-prefix limit even at
// utf8mb4's worst-case 4 bytes/char, while covering effectively any real
// filesystem path or source name this project produces.
// ============================================================================
class MysqlRangeBackend implements RangeBackend {
  private logger: Logger;
  private config: StorageConfig['mysql'];
  // mysql2's callback pool (not the /promise wrapper) so loadAll() below
  // can use real row-at-a-time streaming (see the comment there for why -
  // same "never materialize 10M rows as JS objects at once" reasoning as
  // SqliteSourceRangeTable.loadAll's use of iterate()). `.promise()`
  // wraps this same underlying pool for every other, non-streaming call.
  private pool: any;
  private promisePool: any;

  // Same in-process interning cache as SQLite's SourceInterner - avoids a
  // network round trip on every single addRange-adjacent lookup for a
  // source already seen this run.
  private sourceIdCache = new Map<string, number>();

  constructor(config: StorageConfig['mysql']) {
    this.logger = Logger.getInstance();
    this.config = config;
  }

  async init(): Promise<void> {
    const mysql = require('mysql2');
    this.pool = mysql.createPool({
      host: this.config.host,
      port: this.config.port,
      user: this.config.user,
      password: this.config.password,
      database: this.config.database,
      connectionLimit: this.config.connection_limit || 5,
    });
    this.promisePool = this.pool.promise();

    try {
      await this.promisePool.query(
        'CREATE TABLE IF NOT EXISTS antivpn_range_sources (' +
        'id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY, ' +
        'path VARCHAR(500) NOT NULL, ' +
        'UNIQUE KEY uniq_path (path)' +
        ') ENGINE=InnoDB'
      );
      // Unified blacklist: every bad IPv4 range regardless of origin. `kind`
      // ('list' | 'dataset' | 'operator') keeps the three origins
      // independently replaceable (DELETE ... WHERE kind = ? [AND source_id
      // = ?]) and loadable (loadRangesUnion filters by kind). idx_kind_start
      // makes each kind's ordered union scan an index-only scan.
      await this.promisePool.query(
        'CREATE TABLE IF NOT EXISTS blacklist (' +
        'source_id INT UNSIGNED NOT NULL, ' +
        'kind VARCHAR(16) NOT NULL, ' +
        'start_ip INT UNSIGNED NOT NULL, ' +
        'end_ip INT UNSIGNED NOT NULL, ' +
        'INDEX idx_kind_source (kind, source_id), ' +
        'INDEX idx_kind_start (kind, start_ip, end_ip)' +
        ') ENGINE=InnoDB'
      );
      // Symmetric whitelist table (operator whitelist IPs; `kind` mirrors the
      // blacklist shape so a future bulk whitelist source would slot in the
      // same way).
      await this.promisePool.query(
        'CREATE TABLE IF NOT EXISTS whitelist (' +
        'source_id INT UNSIGNED NOT NULL, ' +
        'kind VARCHAR(16) NOT NULL, ' +
        'start_ip INT UNSIGNED NOT NULL, ' +
        'end_ip INT UNSIGNED NOT NULL, ' +
        'INDEX idx_kind_source (kind, source_id), ' +
        'INDEX idx_kind_start (kind, start_ip, end_ip)' +
        ') ENGINE=InnoDB'
      );
      await this.promisePool.query(
        'CREATE TABLE IF NOT EXISTS antivpn_dataset_ipv6 (' +
        'source_id INT UNSIGNED NOT NULL, ' +
        'kind VARCHAR(8) NOT NULL, ' +
        'value VARCHAR(64) NOT NULL, ' +
        'INDEX idx_source (source_id)' +
        ') ENGINE=InnoDB'
      );
      await this.promisePool.query(
        'CREATE TABLE IF NOT EXISTS antivpn_dataset_asn (' +
        'file_key VARCHAR(500) NOT NULL, ' +
        'label VARCHAR(255) NOT NULL, ' +
        'asn INT UNSIGNED NOT NULL, ' +
        'INDEX idx_file_key (file_key(255))' +
        ') ENGINE=InnoDB'
      );
      await this.promisePool.query(
        'CREATE TABLE IF NOT EXISTS antivpn_asns_table (' +
        'start_ip INT UNSIGNED NOT NULL, ' +
        'end_ip INT UNSIGNED NOT NULL, ' +
        'asn INT UNSIGNED NOT NULL, ' +
        'name VARCHAR(255) NOT NULL, ' +
        "country VARCHAR(2) NOT NULL DEFAULT '', " +
        'INDEX idx_start_cov (start_ip, end_ip, asn, name)' +
        ') ENGINE=InnoDB'
      );
      // One-shot migration for tables created before the country column
      // existed (CREATE TABLE IF NOT EXISTS never alters an existing table).
      // MySQL errors with ER_DUP_FIELDNAME once it's there - ignored.
      try {
        await this.promisePool.query("ALTER TABLE antivpn_asns_table ADD COLUMN country VARCHAR(2) NOT NULL DEFAULT ''");
      } catch (alterErr: any) {
        if (alterErr?.code !== 'ER_DUP_FIELDNAME') throw alterErr;
      }
      await this.promisePool.query(
        'CREATE TABLE IF NOT EXISTS antivpn_list_source_cache (' +
        'name VARCHAR(500) NOT NULL, ' +
        'hash VARCHAR(64) NOT NULL, ' +
        'ip_count INT UNSIGNED NOT NULL, ' +
        'updated_at VARCHAR(64) NOT NULL, ' +
        'PRIMARY KEY (name(255))' +
        ') ENGINE=InnoDB'
      );
      await this.promisePool.query(
        'CREATE TABLE IF NOT EXISTS antivpn_import_file_state (' +
        'path VARCHAR(500) NOT NULL, ' +
        'size BIGINT UNSIGNED NOT NULL, ' +
        'mtime_ms BIGINT UNSIGNED NOT NULL, ' +
        'imported_at VARCHAR(64) NOT NULL, ' +
        'PRIMARY KEY (path(255))' +
        ') ENGINE=InnoDB'
      );
    } catch (e) {
      // Same reasoning as MysqlStorageAdapter.init(): createPool() doesn't
      // itself open a connection, the CREATE TABLE calls above are what
      // do - so a failure here (bad credentials, no access to the target
      // database) leaves this.pool holding a live connection that nothing
      // will otherwise close. End it before rethrowing so createRangeStore
      // below falls back to a genuinely clean SQLite backend.
      try { await this.promisePool.end(); } catch { /* already broken, ignore */ }
      this.pool = undefined;
      this.promisePool = undefined;
      throw e;
    }

    await this.migrateLegacyTables();

    this.logger.info(`RangeIndexStore: using MySQL (${this.config.host}:${this.config.port}/${this.config.database})`);
  }

  // One-time, in-database migration from the pre-consolidation schema
  // (antivpn_list_ranges / antivpn_dataset_ranges / antivpn_asn_table) into
  // the unified blacklist + antivpn_asns_table layout. Done server-side with
  // INSERT ... SELECT so even multi-million-row tables move without round-
  // tripping every row through this process, then the legacy table is
  // dropped so this is a genuine one-shot (a later start finds nothing to
  // migrate). If a step fails it's logged and skipped rather than aborting
  // startup - the background refresh (ListUpdater/DatasetLoader/AsnIndex) will
  // repopulate the new tables on its next pass regardless.
  private async migrateLegacyTables(): Promise<void> {
    const migrations: Array<{ legacy: string; run: () => Promise<void> }> = [
      { legacy: 'antivpn_list_ranges', run: async () => {
        await this.promisePool.query(
          "INSERT INTO blacklist (source_id, kind, start_ip, end_ip) " +
          "SELECT source_id, 'list', start_ip, end_ip FROM antivpn_list_ranges"
        );
      } },
      { legacy: 'antivpn_dataset_ranges', run: async () => {
        await this.promisePool.query(
          "INSERT INTO blacklist (source_id, kind, start_ip, end_ip) " +
          "SELECT source_id, 'dataset', start_ip, end_ip FROM antivpn_dataset_ranges"
        );
      } },
      { legacy: 'antivpn_asn_table', run: async () => {
        await this.promisePool.query(
          "INSERT INTO antivpn_asns_table (start_ip, end_ip, asn, name) " +
          "SELECT start_ip, end_ip, asn, name FROM antivpn_asn_table"
        );
      } },
    ];

    for (const m of migrations) {
      try {
        const [rows] = await this.promisePool.query(
          'SELECT COUNT(*) AS c FROM information_schema.tables WHERE table_schema = ? AND table_name = ?',
          [this.config.database, m.legacy]
        );
        if (Number((rows as any[])[0].c) === 0) continue; // legacy table absent - nothing to migrate
        this.logger.info(`RangeIndexStore: migrating legacy table ${m.legacy} into consolidated schema...`);
        await m.run();
        await this.promisePool.query(`DROP TABLE ${m.legacy}`);
        this.logger.info(`RangeIndexStore: migrated and dropped ${m.legacy}`);
      } catch (e) {
        this.logger.warn(`RangeIndexStore: migration of ${m.legacy} failed (continuing; background refresh will repopulate)`, e);
      }
    }
  }

  // Same LAST_INSERT_ID(id) idiom used for id-interning: this is a single
  // round trip whether the path is new (a real insert, insertId = the new
  // row) or already exists (a no-op update that still reports the
  // existing row's id via insertId, instead of the usual MySQL behavior of
  // insertId being 0/unreliable for a no-op ON DUPLICATE KEY UPDATE).
  private async getOrCreateSourceId(sourcePath: string): Promise<number> {
    const cached = this.sourceIdCache.get(sourcePath);
    if (cached !== undefined) return cached;
    const [result] = await this.promisePool.query(
      'INSERT INTO antivpn_range_sources (path) VALUES (?) ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id)',
      [sourcePath]
    );
    const id = (result as any).insertId as number;
    this.sourceIdCache.set(sourcePath, id);
    return id;
  }

  // InnoDB reports "Deadlock found when trying to get lock" (errno 1213), or
  // occasionally "Lock wait timeout exceeded" (errno 1205), when concurrent
  // transactions contend on the same secondary indexes - exactly what
  // DatasetLoader's 8-way-concurrent per-file persist does against the
  // `blacklist` table (every file DELETEs its own kind='dataset'/source_id
  // rows then bulk-INSERTs the new ones, so eight of those interleave on
  // idx_kind_source / idx_kind_start at once). MySQL's own guidance for both errors is "restart
  // the transaction": the losing transaction is rolled back cleanly, so
  // re-running the whole self-contained op (its own getConnection / BEGIN /
  // COMMIT / rollback) is safe and idempotent. Jittered backoff keeps two
  // simultaneously-deadlocked transactions from immediately re-colliding.
  private static readonly DEADLOCK_RETRY_MAX = 5;

  private async withDeadlockRetry<T>(op: () => Promise<T>): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      try {
        return await op();
      } catch (e: any) {
        const retryable = !!e && (
          e.errno === 1213 || e.errno === 1205 ||
          e.code === 'ER_LOCK_DEADLOCK' || e.code === 'ER_LOCK_WAIT_TIMEOUT'
        );
        if (!retryable || attempt >= MysqlRangeBackend.DEADLOCK_RETRY_MAX) throw e;
        const backoffMs = 25 * (attempt + 1) + Math.floor(Math.random() * 50);
        await new Promise((resolve) => setTimeout(resolve, backoffMs));
      }
    }
  }

  // Curated list ranges and operator datasets both live in the one
  // `blacklist` table now, told apart by the `kind` column so each can still
  // be replaced/loaded independently.
  async replaceListRangesForSource(source: string, ranges: Array<[number, number]>): Promise<void> {
    await this.replaceRangesForSource('blacklist', 'list', source, ranges);
  }

  async loadListRangesUnion(): Promise<{ starts: Uint32Array; ends: Uint32Array }> {
    return this.loadRangesUnion('blacklist', 'list');
  }

  async replaceDatasetRangesForSource(source: string, ranges: Array<[number, number]>): Promise<void> {
    await this.replaceRangesForSource('blacklist', 'dataset', source, ranges);
  }

  async loadDatasetRangesUnion(): Promise<{ starts: Uint32Array; ends: Uint32Array }> {
    return this.loadRangesUnion('blacklist', 'dataset');
  }

  // Fixed sentinel source name for the operator-managed rows (kind =
  // 'operator'), which are replaced wholesale rather than per-source - see
  // replaceOperatorBlacklist/Whitelist below.
  private static readonly OPERATOR_SOURCE = '__operator__';

  async replaceOperatorBlacklist(ranges: Array<[number, number]>): Promise<void> {
    await this.replaceRangesForSource('blacklist', 'operator', MysqlRangeBackend.OPERATOR_SOURCE, ranges);
  }

  async replaceOperatorWhitelist(ranges: Array<[number, number]>): Promise<void> {
    await this.replaceRangesForSource('whitelist', 'operator', MysqlRangeBackend.OPERATOR_SOURCE, ranges);
  }

  private static readonly WRITE_BATCH_SIZE = 5_000; // multi-row INSERT batch - keeps well under max_allowed_packet

  // Replaces exactly the (kind, source) slice of `table`: one source's rows
  // of one kind, atomically. Scoping the DELETE by BOTH kind and source_id
  // means a list source and a dataset source that happen to share a
  // source_id (they can't today, but the schema doesn't forbid it) never
  // clobber each other, and the operator wholesale-replace only ever touches
  // its own kind='operator' rows.
  private async replaceRangesForSource(table: string, kind: string, source: string, ranges: Array<[number, number]>): Promise<void> {
    const sourceId = await this.getOrCreateSourceId(source);
    await this.withDeadlockRetry(async () => {
      const conn = await this.promisePool.getConnection();
      try {
        await conn.beginTransaction();
        await conn.query(`DELETE FROM ${table} WHERE kind = ? AND source_id = ?`, [kind, sourceId]);
        for (let i = 0; i < ranges.length; i += MysqlRangeBackend.WRITE_BATCH_SIZE) {
          const batch = ranges.slice(i, i + MysqlRangeBackend.WRITE_BATCH_SIZE);
          if (batch.length === 0) continue;
          const rows = batch.map(([start, end]) => [sourceId, kind, start, end]);
          await conn.query(`INSERT INTO ${table} (source_id, kind, start_ip, end_ip) VALUES ?`, [rows]);
        }
        await conn.commit();
      } catch (e) {
        await conn.rollback();
        throw e;
      } finally {
        conn.release();
      }
    });
  }

  // Streaming union scan of one kind within a table (see the file-level
  // comment on why loadAll-style reads use the raw callback pool rather than
  // the promise wrapper) - one COUNT(*) to pre-size the typed arrays, then
  // one ordered SELECT streamed row-by-row into them, mirroring
  // SqliteSourceRangeTable's iterate()-based approach so this never holds
  // more than a handful of in-flight row objects at once regardless of
  // table size.
  private loadRangesUnion(table: string, kind: string): Promise<{ starts: Uint32Array; ends: Uint32Array }> {
    return new Promise((resolve, reject) => {
      this.pool.query(`SELECT COUNT(*) as c FROM ${table} WHERE kind = ?`, [kind], (err: any, countRows: any) => {
        if (err) return reject(err);
        const n = Number(countRows[0].c);
        const starts = new Uint32Array(n);
        const ends = new Uint32Array(n);
        let i = 0;
        const query = this.pool.query(`SELECT start_ip, end_ip FROM ${table} WHERE kind = ? ORDER BY start_ip`, [kind]);
        query
          .on('error', (streamErr: any) => reject(streamErr))
          .on('result', (row: any) => {
            starts[i] = row.start_ip;
            ends[i] = row.end_ip;
            i++;
          })
          .on('end', () => resolve({ starts, ends }));
      });
    });
  }

  async replaceDatasetIpv6ForSource(source: string, entries: Ipv6Entry[]): Promise<void> {
    const sourceId = await this.getOrCreateSourceId(source);
    await this.withDeadlockRetry(async () => {
      const conn = await this.promisePool.getConnection();
      try {
        await conn.beginTransaction();
        await conn.query('DELETE FROM antivpn_dataset_ipv6 WHERE source_id = ?', [sourceId]);
        for (let i = 0; i < entries.length; i += MysqlRangeBackend.WRITE_BATCH_SIZE) {
          const batch = entries.slice(i, i + MysqlRangeBackend.WRITE_BATCH_SIZE);
          if (batch.length === 0) continue;
          const rows = batch.map((e) => [sourceId, e.kind, e.value]);
          await conn.query('INSERT INTO antivpn_dataset_ipv6 (source_id, kind, value) VALUES ?', [rows]);
        }
        await conn.commit();
      } catch (e) {
        await conn.rollback();
        throw e;
      } finally {
        conn.release();
      }
    });
  }

  async loadDatasetIpv6Union(): Promise<Ipv6Entry[]> {
    const [rows] = await this.promisePool.query('SELECT kind, value FROM antivpn_dataset_ipv6');
    return rows as Ipv6Entry[];
  }

  async replaceDatasetAsnForFile(fileKey: string, entries: Array<{ asn: number; label: string }>): Promise<void> {
    await this.withDeadlockRetry(async () => {
      const conn = await this.promisePool.getConnection();
      try {
        await conn.beginTransaction();
        await conn.query('DELETE FROM antivpn_dataset_asn WHERE file_key = ?', [fileKey]);
        for (let i = 0; i < entries.length; i += MysqlRangeBackend.WRITE_BATCH_SIZE) {
          const batch = entries.slice(i, i + MysqlRangeBackend.WRITE_BATCH_SIZE);
          if (batch.length === 0) continue;
          const rows = batch.map((e) => [fileKey, e.label, e.asn]);
          await conn.query('INSERT INTO antivpn_dataset_asn (file_key, label, asn) VALUES ?', [rows]);
        }
        await conn.commit();
      } catch (e) {
        await conn.rollback();
        throw e;
      } finally {
        conn.release();
      }
    });
  }

  async loadDatasetAsnUnion(): Promise<Map<number, string>> {
    const [rows] = await this.promisePool.query('SELECT label, asn FROM antivpn_dataset_asn');
    const map = new Map<number, string>();
    for (const row of rows as Array<{ label: string; asn: number }>) if (!map.has(row.asn)) map.set(row.asn, row.label);
    return map;
  }

  async replaceAsnTable(rows: AsnTableRow[]): Promise<void> {
    await this.withDeadlockRetry(async () => {
      const conn = await this.promisePool.getConnection();
      try {
        await conn.beginTransaction();
        await conn.query('DELETE FROM antivpn_asns_table');
        for (let i = 0; i < rows.length; i += MysqlRangeBackend.WRITE_BATCH_SIZE) {
          const batch = rows.slice(i, i + MysqlRangeBackend.WRITE_BATCH_SIZE);
          if (batch.length === 0) continue;
          const values = batch.map((r) => [r.start, r.end, r.asn, r.name, r.country || '']);
          await conn.query('INSERT INTO antivpn_asns_table (start_ip, end_ip, asn, name, country) VALUES ?', [values]);
        }
        await conn.commit();
      } catch (e) {
        await conn.rollback();
        throw e;
      } finally {
        conn.release();
      }
    });
  }

  async loadAsnTable(): Promise<AsnTableRow[]> {
    const [rows] = await this.promisePool.query(
      'SELECT start_ip as start, end_ip as `end`, asn, name, country FROM antivpn_asns_table ORDER BY start_ip'
    );
    return rows as AsnTableRow[];
  }

  async isFileUnchanged(filePath: string, size: number, mtimeMs: number): Promise<boolean> {
    const [rows] = await this.promisePool.query(
      'SELECT size, mtime_ms as mtimeMs FROM antivpn_import_file_state WHERE path = ?',
      [filePath]
    );
    const row = (rows as any[])[0];
    return !!row && Number(row.size) === size && Number(row.mtimeMs) === mtimeMs;
  }

  async markFileImported(filePath: string, size: number, mtimeMs: number): Promise<void> {
    await this.promisePool.query(
      'INSERT INTO antivpn_import_file_state (path, size, mtime_ms, imported_at) VALUES (?, ?, ?, ?) ' +
      'ON DUPLICATE KEY UPDATE size = VALUES(size), mtime_ms = VALUES(mtime_ms), imported_at = VALUES(imported_at)',
      [filePath, size, mtimeMs, new Date().toISOString()]
    );
  }

  async getSourceCacheHash(name: string): Promise<{ hash: string; ipCount: number } | null> {
    const [rows] = await this.promisePool.query(
      'SELECT hash, ip_count as ipCount FROM antivpn_list_source_cache WHERE name = ?',
      [name]
    );
    const row = (rows as any[])[0];
    return row ? { hash: row.hash, ipCount: Number(row.ipCount) } : null;
  }

  async setSourceCacheHash(name: string, hash: string, ipCount: number): Promise<void> {
    await this.promisePool.query(
      'INSERT INTO antivpn_list_source_cache (name, hash, ip_count, updated_at) VALUES (?, ?, ?, ?) ' +
      'ON DUPLICATE KEY UPDATE hash = VALUES(hash), ip_count = VALUES(ip_count), updated_at = VALUES(updated_at)',
      [name, hash, ipCount, new Date().toISOString()]
    );
  }

  async getAllSourceCacheHashes(): Promise<Map<string, { hash: string; ipCount: number }>> {
    const [rows] = await this.promisePool.query('SELECT name, hash, ip_count as ipCount FROM antivpn_list_source_cache');
    const map = new Map<string, { hash: string; ipCount: number }>();
    for (const row of rows as Array<{ name: string; hash: string; ipCount: number }>) {
      map.set(row.name, { hash: row.hash, ipCount: Number(row.ipCount) });
    }
    return map;
  }

  // For the streaming session (DatasetLoader's per-line addRange calls -
  // see the file-level comment on why addRange stays synchronous), pending
  // batches are chained onto one another rather than awaited individually:
  // addRange() never blocks the parse loop, but finish() awaits the whole
  // chain, so every batch a session ever kicked off is guaranteed to have
  // landed (or thrown) before finish() resolves.
  async beginDatasetRangeSession(source: string): Promise<RangeWriteSession> {
    const sourceId = await this.getOrCreateSourceId(source);
    let deleted = false;
    let batchStarts: number[] = [];
    let batchEnds: number[] = [];
    let chain: Promise<void> = Promise.resolve();

    const flush = (): void => {
      if (batchStarts.length === 0 && deleted) return; // nothing pending, already cleared
      const starts = batchStarts;
      const ends = batchEnds;
      const needsDelete = !deleted;
      deleted = true;
      batchStarts = [];
      batchEnds = [];
      chain = chain.then(() => this.withDeadlockRetry(async () => {
        const conn = await this.promisePool.getConnection();
        try {
          await conn.beginTransaction();
          if (needsDelete) await conn.query("DELETE FROM blacklist WHERE kind = 'dataset' AND source_id = ?", [sourceId]);
          if (starts.length > 0) {
            const rows = starts.map((s, idx) => [sourceId, 'dataset', s, ends[idx]]);
            await conn.query('INSERT INTO blacklist (source_id, kind, start_ip, end_ip) VALUES ?', [rows]);
          }
          await conn.commit();
        } catch (e) {
          await conn.rollback();
          throw e;
        } finally {
          conn.release();
        }
      }));
    };

    return {
      addRange: (start: number, end: number): void => {
        batchStarts.push(start);
        batchEnds.push(end);
        if (batchStarts.length >= MysqlRangeBackend.WRITE_BATCH_SIZE) flush();
      },
      finish: async (): Promise<void> => {
        flush();
        await chain;
      },
    };
  }

  async close(): Promise<void> {
    if (this.promisePool) await this.promisePool.end();
  }
}

// ============================================================================
// FACTORY + PUBLIC STORE - picks a backend based on config.json's
// storage.type, same fail-open posture as createStorageAdapter: a MySQL
// misconfiguration falls back to SQLite with a warning rather than
// preventing the bot from starting.
// ============================================================================
export class RangeIndexStore {
  private static instance: RangeIndexStore | null = null;
  private logger: Logger;
  private impl!: RangeBackend;

  private constructor() {
    this.logger = Logger.getInstance();
  }

  static getInstance(): RangeIndexStore {
    if (!RangeIndexStore.instance) RangeIndexStore.instance = new RangeIndexStore();
    return RangeIndexStore.instance;
  }

  async init(storageConfig?: StorageConfig, dbPath: string = path.join(process.cwd(), 'data', 'ranges.sqlite')): Promise<void> {
    if (storageConfig?.type === 'mysql') {
      try {
        const backend = new MysqlRangeBackend(storageConfig.mysql);
        await backend.init();
        this.impl = backend;
        return;
      } catch (e) {
        this.logger.warn('RangeIndexStore: failed to initialize MySQL backend, falling back to SQLite', e);
      }
    }
    const backend = new SqliteRangeBackend();
    await backend.init(dbPath);
    this.impl = backend;
  }

  // ==========================================================================
  // blacklist (kind='list') - ListUpdater's curated bulk sources (X4BNet,
  // FireHOL, per-ASN prefix downloads, official cloud-provider ranges, ...).
  // On MySQL these share the one `blacklist` table with the dataset and
  // operator ranges; on SQLite/file they keep their own list_ranges table.
  // ==========================================================================
  replaceListRangesForSource(source: string, ranges: Array<[number, number]>): Promise<void> {
    return this.impl.replaceListRangesForSource(source, ranges);
  }

  loadListRangesUnion(): Promise<{ starts: Uint32Array; ends: Uint32Array }> {
    return this.impl.loadListRangesUnion();
  }

  // ==========================================================================
  // blacklist (kind='dataset') / dataset_ipv6 / dataset_asn - DatasetLoader's
  // operator datasets (data/datasets)
  // ==========================================================================
  replaceDatasetRangesForSource(source: string, ranges: Array<[number, number]>): Promise<void> {
    return this.impl.replaceDatasetRangesForSource(source, ranges);
  }

  // Streaming variant - see RangeWriteSession's doc comment. Used by
  // DatasetLoader instead of replaceDatasetRangesForSource so a
  // multi-million-line file never needs its whole range list materialized
  // in one JS array at once.
  beginDatasetRangeSession(source: string): Promise<RangeWriteSession> {
    return this.impl.beginDatasetRangeSession(source);
  }

  loadDatasetRangesUnion(): Promise<{ starts: Uint32Array; ends: Uint32Array }> {
    return this.impl.loadDatasetRangesUnion();
  }

  replaceDatasetIpv6ForSource(source: string, entries: Ipv6Entry[]): Promise<void> {
    return this.impl.replaceDatasetIpv6ForSource(source, entries);
  }

  loadDatasetIpv6Union(): Promise<Ipv6Entry[]> {
    return this.impl.loadDatasetIpv6Union();
  }

  // Replaces every ASN row attributed to one outer dataset file (fileKey) -
  // a zip's many inner entries all share the same fileKey (the zip itself,
  // since that's the change-detection granularity - see
  // DatasetLoader.persistContext) while each entry keeps its own label.
  replaceDatasetAsnForFile(fileKey: string, entries: Array<{ asn: number; label: string }>): Promise<void> {
    return this.impl.replaceDatasetAsnForFile(fileKey, entries);
  }

  // First label seen for a given ASN wins, matching DatasetLoader's
  // existing "if (this.pendingAsn.has(token.value)) return 'duplicate'"
  // first-writer-wins semantics.
  loadDatasetAsnUnion(): Promise<Map<number, string>> {
    return this.impl.loadDatasetAsnUnion();
  }

  // ==========================================================================
  // asn_table - AsnIndex's iptoasn.com bulk table (wholesale replace on
  // every ~24h refresh, no per-source bookkeeping needed)
  // ==========================================================================
  replaceAsnTable(rows: AsnTableRow[]): Promise<void> {
    return this.impl.replaceAsnTable(rows);
  }

  loadAsnTable(): Promise<AsnTableRow[]> {
    return this.impl.loadAsnTable();
  }

  // ==========================================================================
  // Operator-managed blacklist/whitelist mirror - ListManager's small
  // operator lists, mirrored into the same unified blacklist/whitelist tables
  // (kind = 'operator') the bulk list/dataset ranges live in. MySQL-only; a
  // no-op on the SQLite/file backends, where these lists persist as JSON
  // documents via StorageAdapter instead.
  // ==========================================================================
  replaceOperatorBlacklist(ranges: Array<[number, number]>): Promise<void> {
    return this.impl.replaceOperatorBlacklist(ranges);
  }

  replaceOperatorWhitelist(ranges: Array<[number, number]>): Promise<void> {
    return this.impl.replaceOperatorWhitelist(ranges);
  }

  // ==========================================================================
  // import_file_state - DatasetLoader's skip-unchanged-files bookkeeping
  // ==========================================================================
  isFileUnchanged(filePath: string, size: number, mtimeMs: number): Promise<boolean> {
    return this.impl.isFileUnchanged(filePath, size, mtimeMs);
  }

  markFileImported(filePath: string, size: number, mtimeMs: number): Promise<void> {
    return this.impl.markFileImported(filePath, size, mtimeMs);
  }

  // ==========================================================================
  // list_source_cache - ListUpdater's change-detection (a hash/count per
  // source, not the source's full IP array - see ListUpdater's own
  // in-memory mirror of this table, populated via getAllSourceCacheHashes
  // once at startup rather than one round trip per source per check)
  // ==========================================================================
  getSourceCacheHash(name: string): Promise<{ hash: string; ipCount: number } | null> {
    return this.impl.getSourceCacheHash(name);
  }

  setSourceCacheHash(name: string, hash: string, ipCount: number): Promise<void> {
    return this.impl.setSourceCacheHash(name, hash, ipCount);
  }

  getAllSourceCacheHashes(): Promise<Map<string, { hash: string; ipCount: number }>> {
    return this.impl.getAllSourceCacheHashes();
  }

  async close(): Promise<void> {
    if (this.impl) await this.impl.close();
  }
}
