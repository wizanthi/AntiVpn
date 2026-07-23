// src/services/StorageAdapter.ts
//
// Pluggable persistence backend for the small, operator-managed stores
// (blacklist, whitelist, custombans, ip_reputation, network_reputation,
// checked_ips) - see StorageConfig in types/index.ts. Every store already
// treats its data as one JSON document rewritten wholesale on every save
// (see ListManager/CustomBanManager/IpReputationStore/
// NetworkReputationStore/CacheService), so every backend here just maps
// "logical store name" -> "the current JSON document for it": one row per
// store, holding the serialized document, in a single antivpn_store table
// for the two database backends.
//
// This does NOT cover the multi-million-entry curated bulk lists
// (ListUpdater's static index, DatasetLoader's dataset index, AsnIndex) -
// those stay in-memory-only regardless of storage.type, same as today.
import * as fs from 'fs';
import * as path from 'path';
import { Logger } from '../utils/Logger';
import { StorageConfig } from '../types';

export interface StorageAdapter {
  readonly kind: 'file' | 'sqlite' | 'mysql';
  init(): Promise<void>;
  // Returns the parsed JSON document for this store name, or null if it
  // doesn't exist yet (a store treats null the same as "first run").
  read(name: string): Promise<any | null>;
  write(name: string, data: any): Promise<void>;
  close(): Promise<void>;
}

// ============================================================================
// FILE (default) - the pre-existing behavior, factored out of the five
// stores that used to each hand-roll this same atomic temp-file+rename
// pattern individually.
// ============================================================================
export class FileStorageAdapter implements StorageAdapter {
  readonly kind = 'file' as const;
  private logger: Logger;
  private dir: string;

  constructor(dir: string = path.join(process.cwd(), 'data')) {
    this.logger = Logger.getInstance();
    this.dir = dir;
  }

  // Monotonic per-process counter so two concurrent writes to the same
  // store name never collide on one temp path (the old `.${pid}.tmp` scheme
  // did: a second in-flight write would truncate the first's temp file,
  // then one rename would ENOENT).
  private tmpSeq: number = 0;

  async init(): Promise<void> {
    if (!fs.existsSync(this.dir)) fs.mkdirSync(this.dir, { recursive: true });
    // Reap stale temp files left behind by a process that was killed
    // mid-write (SIGKILL between writeFile and rename) - otherwise these
    // 0-byte `.tmp` remnants accumulate in data/ forever.
    try {
      for (const f of fs.readdirSync(this.dir)) {
        if (/\.\d+\.\d+\.tmp$/.test(f) || /\.\d+\.tmp$/.test(f)) {
          try { fs.unlinkSync(path.join(this.dir, f)); } catch { /* ignore */ }
        }
      }
    } catch { /* best-effort cleanup only */ }
  }

  private pathFor(name: string): string {
    return path.join(this.dir, `${name}.json`);
  }

  async read(name: string): Promise<any | null> {
    const filePath = this.pathFor(name);
    try {
      if (!fs.existsSync(filePath)) return null;
      const raw = fs.readFileSync(filePath, 'utf-8');
      if (raw.trim().length === 0) return null; // truncated/empty file - treat as absent
      return JSON.parse(raw);
    } catch (e) {
      this.logger.warn(`FileStorageAdapter: failed to read ${filePath}, treating as empty`, e);
      return null;
    }
  }

  // Per-store-name write serialization. On Windows, two concurrent renames
  // targeting the SAME destination file throw EPERM (rename-over-existing is
  // not safe under concurrency there) - which is exactly what left 0-byte
  // temp remnants behind. Chaining writes per name guarantees at most one
  // temp->final rename to a given path is ever in flight, independent of
  // whether the calling store happens to serialize its own saves.
  private writeChains: Map<string, Promise<void>> = new Map();

  // Written to a temp file and renamed into place, same reasoning every
  // store used individually before this abstraction existed: a direct write
  // left a truncated/corrupt file (and data silently reverted on next boot)
  // if the process was killed mid-write.
  async write(name: string, data: any): Promise<void> {
    const prev = this.writeChains.get(name) || Promise.resolve();
    // Swallow the previous write's rejection here so one failed write doesn't
    // reject every subsequent queued write on the same store; each caller
    // still sees its own write's own outcome via the returned promise.
    const next = prev.catch(() => {}).then(() => this.writeInternal(name, data));
    this.writeChains.set(name, next);
    next.catch(() => {}).finally(() => {
      if (this.writeChains.get(name) === next) this.writeChains.delete(name);
    });
    return next;
  }

  private async writeInternal(name: string, data: any): Promise<void> {
    const filePath = this.pathFor(name);
    if (!fs.existsSync(this.dir)) fs.mkdirSync(this.dir, { recursive: true });
    // Compact (no pretty-print): these are machine-owned stores rewritten
    // wholesale on every save (some, like checked_ips, on a large fraction
    // of every connection) - the extra CPU/bytes indentation costs buys no
    // benefit, since no operator hand-edits these files.
    const payload = JSON.stringify(data);
    // Unique per-write temp name (pid + monotonic counter) so concurrent
    // writes to the same store never share a temp file.
    const tmpPath = `${filePath}.${process.pid}.${this.tmpSeq++}.tmp`;
    try {
      await fs.promises.writeFile(tmpPath, payload, 'utf-8');
      await fs.promises.rename(tmpPath, filePath);
    } catch (e) {
      // Best-effort cleanup so a failed rename (e.g. a transient EPERM from
      // an AV scanner holding the destination on Windows) doesn't leave the
      // temp file behind to accumulate.
      try { await fs.promises.unlink(tmpPath); } catch { /* already gone */ }
      throw e;
    }
  }

  async close(): Promise<void> {
    // No open resource to release.
  }
}

// ============================================================================
// SQLITE - Node's built-in node:sqlite (DatabaseSync), no extra dependency.
// Requires Node >= 22.5 (verified available on this project's Node
// version); createStorageAdapter falls back to file storage with a warning
// if it isn't available.
// ============================================================================
class SqliteStorageAdapter implements StorageAdapter {
  readonly kind = 'sqlite' as const;
  private logger: Logger;
  private dbPath: string;
  private db: any;
  private selectStmt: any;
  private upsertStmt: any;

  constructor(dbPath: string) {
    this.logger = Logger.getInstance();
    this.dbPath = path.isAbsolute(dbPath) ? dbPath : path.join(process.cwd(), dbPath);
  }

  async init(): Promise<void> {
    const { DatabaseSync } = require('node:sqlite');
    const dir = path.dirname(this.dbPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    this.db = new DatabaseSync(this.dbPath);
    try {
      this.db.exec(
        'CREATE TABLE IF NOT EXISTS antivpn_store (name TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at TEXT NOT NULL)'
      );
      this.selectStmt = this.db.prepare('SELECT data FROM antivpn_store WHERE name = ?');
      this.upsertStmt = this.db.prepare(
        'INSERT INTO antivpn_store (name, data, updated_at) VALUES (?, ?, ?) ' +
        'ON CONFLICT(name) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at'
      );
    } catch (e) {
      // Same reasoning as MysqlStorageAdapter.init(): createStorageAdapter
      // discards this instance on failure and falls back to file storage,
      // so an open handle here (e.g. the file exists but is a locked/
      // corrupt/non-SQLite file) would otherwise leak for the process's
      // whole lifetime.
      try { this.db.close(); } catch { /* already broken, ignore */ }
      this.db = undefined;
      throw e;
    }
    this.logger.info(`StorageAdapter: using SQLite (${this.dbPath})`);
  }

  async read(name: string): Promise<any | null> {
    const row = this.selectStmt.get(name) as { data: string } | undefined;
    if (!row) return null;
    try {
      return JSON.parse(row.data);
    } catch (e) {
      this.logger.warn(`SqliteStorageAdapter: failed to parse stored data for "${name}", treating as empty`, e);
      return null;
    }
  }

  async write(name: string, data: any): Promise<void> {
    this.upsertStmt.run(name, JSON.stringify(data), new Date().toISOString());
  }

  async close(): Promise<void> {
    if (this.db) this.db.close();
  }
}

// ============================================================================
// MYSQL - lazy-required "mysql2" (optionalDependency, same fail-open
// pattern DatasetLoader already uses for adm-zip/maxmind/parquetjs-lite):
// if the package isn't installed or the connection fails, createStorageAdapter
// falls back to file storage rather than crashing the bot.
// ============================================================================
class MysqlStorageAdapter implements StorageAdapter {
  readonly kind = 'mysql' as const;
  private logger: Logger;
  private config: StorageConfig['mysql'];
  private pool: any;

  constructor(config: StorageConfig['mysql']) {
    this.logger = Logger.getInstance();
    this.config = config;
  }

  async init(): Promise<void> {
    const mysql = require('mysql2/promise');
    this.pool = mysql.createPool({
      host: this.config.host,
      port: this.config.port,
      user: this.config.user,
      password: this.config.password,
      database: this.config.database,
      connectionLimit: this.config.connection_limit || 5,
    });
    try {
      await this.pool.query(
        'CREATE TABLE IF NOT EXISTS antivpn_store (' +
        'name VARCHAR(255) PRIMARY KEY, data LONGTEXT NOT NULL, updated_at VARCHAR(64) NOT NULL' +
        ')'
      );
    } catch (e) {
      // createPool() doesn't actually open a connection - the CREATE TABLE
      // query above is what does, so a failure here (bad credentials, no
      // access to the target database, etc.) leaves this.pool holding a
      // live connection that nothing will ever close: createStorageAdapter
      // catches this rejection and falls back to FileStorageAdapter,
      // discarding this instance entirely, and mysql2's pool has no
      // finalizer to clean itself up. Left alone this leaks one open
      // connection to the MySQL server on every single restart that hits
      // bad config. End the pool before rethrowing so the caller's
      // fallback is actually clean.
      try { await this.pool.end(); } catch { /* already broken, ignore */ }
      this.pool = undefined;
      throw e;
    }
    this.logger.info(`StorageAdapter: using MySQL (${this.config.host}:${this.config.port}/${this.config.database})`);
  }

  async read(name: string): Promise<any | null> {
    const [rows] = await this.pool.query('SELECT data FROM antivpn_store WHERE name = ?', [name]);
    const row = (rows as any[])[0];
    if (!row) return null;
    try {
      return JSON.parse(row.data);
    } catch (e) {
      this.logger.warn(`MysqlStorageAdapter: failed to parse stored data for "${name}", treating as empty`, e);
      return null;
    }
  }

  async write(name: string, data: any): Promise<void> {
    await this.pool.query(
      'INSERT INTO antivpn_store (name, data, updated_at) VALUES (?, ?, ?) ' +
      'ON DUPLICATE KEY UPDATE data = VALUES(data), updated_at = VALUES(updated_at)',
      [name, JSON.stringify(data), new Date().toISOString()]
    );
  }

  async close(): Promise<void> {
    if (this.pool) await this.pool.end();
  }
}

// ============================================================================
// FACTORY - a DB misconfiguration (missing driver, bad credentials,
// unsupported Node version) must never stop the bot from starting, so any
// failure here logs a clear warning and falls back to FileStorageAdapter.
// ============================================================================
export async function createStorageAdapter(config: StorageConfig | undefined): Promise<StorageAdapter> {
  const logger = Logger.getInstance();
  const type = config?.type || 'file';

  if (type === 'sqlite') {
    try {
      const adapter = new SqliteStorageAdapter(config!.sqlite.path);
      await adapter.init();
      return adapter;
    } catch (e) {
      logger.warn('StorageAdapter: failed to initialize SQLite backend, falling back to file storage', e);
    }
  } else if (type === 'mysql') {
    try {
      const adapter = new MysqlStorageAdapter(config!.mysql);
      await adapter.init();
      return adapter;
    } catch (e) {
      logger.warn('StorageAdapter: failed to initialize MySQL backend, falling back to file storage', e);
    }
  }

  const fileAdapter = new FileStorageAdapter();
  await fileAdapter.init();
  return fileAdapter;
}
