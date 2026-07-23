// src/services/AsnIndex.ts
//
// Offline IP -> ASN lookup table.
//
// WHY: IpChecker previously called api.iptoasn.com over HTTPS for every
// single non-cached player IP just to learn which ASN announces it. That
// round trip (up to the full 3.5s timeout on a slow/rate-limited response)
// sat on the critical path of every new connection.
//
// The same data iptoasn.com serves live is also published in bulk as a
// plain TSV dump (https://iptoasn.com/data/ip2asn-v4.tsv.gz), refreshed
// roughly every 24h. Downloading that once and holding it as a sorted,
// binary-searchable range table turns "ASN of this IP" from a network call
// into a synchronous, sub-millisecond, zero-failure-mode local lookup -
// strictly faster and strictly more reliable (no per-connection dependency
// on a third-party API being up or unthrottled).
//
// This index is used for exactly one purpose: identifying which network
// (ASN) announces an IP, a verifiable technical/BGP fact. Whether that ASN
// is treated as hosting/VPN infrastructure is still decided entirely by
// ProviderLists.VERIFIED_HOSTING_VPN_ASNS - an explicitly curated allowlist
// of ASNs individually confirmed to have no residential subscriber base.
// This module never guesses; it only answers "what ASN is this IP in".
//
// PERSISTENCE: the ~500k-1M row bulk table is written to RangeIndexStore
// (see that file) after every successful download, and loaded back from
// there at startup - so a restart has a populated table instantly instead
// of starting empty until the next 24h-cadence download finishes. Held at
// runtime as parallel typed arrays (Uint32Array start/end/asn, plus a
// deduplicated name string table indexed by a Uint32Array) instead of an
// array of {start,end,asn,name} objects - the same organization's name
// string is repeated across every one of its announced prefixes, so
// interning it once per unique name instead of once per range is both a
// large memory win and removes millions of duplicate string allocations.
import axios, { AxiosInstance } from 'axios';
import * as zlib from 'zlib';
import { Logger } from '../utils/Logger';
import { binarySearchIndex } from './RangeTable';
import { RangeIndexStore, AsnTableRow } from './RangeIndexStore';
import { sharedKeepAliveHttpAgent, sharedKeepAliveHttpsAgent } from '../utils/HttpAgents';

export class AsnIndex {
  private static instance: AsnIndex | null = null;
  private logger: Logger;
  private store: RangeIndexStore;
  private httpClient: AxiosInstance;

  private starts: Uint32Array = new Uint32Array(0);
  private ends: Uint32Array = new Uint32Array(0);
  private asns: Uint32Array = new Uint32Array(0);
  private nameIdx: Uint32Array = new Uint32Array(0);
  private names: string[] = [];
  // Interned ISO-2 country codes, same scheme as names above - ~250
  // distinct values across the whole table, so a per-range index into a
  // tiny string array instead of a per-range string.
  private countryIdx: Uint32Array = new Uint32Array(0);
  private countries: string[] = [];

  private loadedAt: number = 0;
  private refreshMs: number = 24 * 60 * 60 * 1000; // 24h - matches upstream update cadence
  private refreshing: Promise<void> | null = null;
  private refreshTimer: NodeJS.Timeout | null = null;
  private readonly sourceUrl = 'https://iptoasn.com/data/ip2asn-v4.tsv.gz';

  private constructor() {
    this.logger = Logger.getInstance();
    this.store = RangeIndexStore.getInstance();
    // Shared keep-alive agent (see utils/HttpAgents.ts) - this is a single
    // large download, but reuses the same pool as every other outbound
    // HTTP client in this project and avoids a cold TLS handshake if
    // init()/refresh() ever run more than once in the same process (e.g. a
    // manual forced refresh).
    this.httpClient = axios.create({
      httpAgent: sharedKeepAliveHttpAgent,
      httpsAgent: sharedKeepAliveHttpsAgent,
      headers: { 'User-Agent': 'WizanthiAntiVpn/AsnIndex' },
    });
  }

  static getInstance(): AsnIndex {
    if (!AsnIndex.instance) AsnIndex.instance = new AsnIndex();
    return AsnIndex.instance;
  }

  // Loads whatever was persisted from the last successful refresh - near-
  // instant (one bulk ordered SELECT, no network, no decompression), so the
  // very first player connections after a restart already have ASN data
  // available instead of racing an empty table against the first download.
  async loadFromStore(): Promise<void> {
    const rows = await this.store.loadAsnTable();
    this.applyRows(rows);
    if (rows.length > 0) {
      this.logger.info(`AsnIndex: loaded ${rows.length} ranges from local store (instant, no download)`);
    }
  }

  // Call once at startup to kick off the background refresh loop. Safe to
  // call speculatively/repeatedly - refresh() is idempotent while a
  // download is already in flight. Never awaited by the startup sequence
  // (see index.ts) - loadFromStore() above already made data available.
  async init(): Promise<void> {
    await this.refresh().catch((e) => {
      this.logger.warn('AsnIndex: initial refresh failed, using whatever loadFromStore() provided (if anything)', e);
    });
    // Background refresh loop - never blocks a caller. Guarded so repeated
    // init() calls (documented as safe) don't stack multiple intervals, and
    // unref()'d so this timer alone never keeps the process alive at exit -
    // same posture as DatasetLoader.startAutoReload().
    if (!this.refreshTimer) {
      this.refreshTimer = setInterval(() => {
        if (Date.now() - this.loadedAt > this.refreshMs) {
          this.refresh().catch(() => {});
        }
      }, 60 * 60 * 1000); // check hourly, only actually re-download once stale
      if (typeof this.refreshTimer.unref === 'function') this.refreshTimer.unref();
    }
  }

  // Synchronous, in-memory lookup - O(log n). Returns null if the table
  // hasn't loaded yet or the IP isn't covered (e.g. IPv6, not handled by
  // this fast path).
  lookup(ip: string): { asn: number; name: string; country: string } | null {
    if (ip.includes(':')) return null; // IPv6 not covered by this fast path
    const num = this.ipToNumber(ip);
    if (num === null) return null;
    const idx = binarySearchIndex(this.starts, this.ends, num);
    if (idx === -1) return null;
    return { asn: this.asns[idx], name: this.names[this.nameIdx[idx]], country: this.countries[this.countryIdx[idx]] || '' };
  }

  getStats() {
    return { ranges: this.starts.length, loaded_at: this.loadedAt ? new Date(this.loadedAt).toISOString() : null };
  }

  private applyRows(rows: AsnTableRow[]): void {
    const n = rows.length;
    const starts = new Uint32Array(n);
    const ends = new Uint32Array(n);
    const asns = new Uint32Array(n);
    const nameIdx = new Uint32Array(n);
    const nameToIdx = new Map<string, number>();
    const names: string[] = [];
    const countryIdx = new Uint32Array(n);
    const countryToIdx = new Map<string, number>();
    const countries: string[] = [];
    for (let i = 0; i < n; i++) {
      const r = rows[i];
      starts[i] = r.start;
      ends[i] = r.end;
      asns[i] = r.asn;
      let idx = nameToIdx.get(r.name);
      if (idx === undefined) {
        idx = names.length;
        names.push(r.name);
        nameToIdx.set(r.name, idx);
      }
      nameIdx[i] = idx;
      const country = r.country || '';
      let cIdx = countryToIdx.get(country);
      if (cIdx === undefined) {
        cIdx = countries.length;
        countries.push(country);
        countryToIdx.set(country, cIdx);
      }
      countryIdx[i] = cIdx;
    }
    this.starts = starts;
    this.ends = ends;
    this.asns = asns;
    this.nameIdx = nameIdx;
    this.names = names;
    this.countryIdx = countryIdx;
    this.countries = countries;
  }

  private async refresh(): Promise<void> {
    if (this.refreshing) return this.refreshing;
    this.refreshing = (async () => {
      const started = Date.now();
      // Bounded on both ends: maxContentLength/maxBodyLength cap the
      // compressed download (the real file is a few MB; anything
      // dramatically larger means the upstream/DNS/TLS chain isn't serving
      // what it should), and maxOutputLength caps the decompressed size
      // zlib will produce - without it, a compromised or hijacked upstream
      // could return a small gzip bomb that expands to gigabytes and OOMs
      // the whole bot from a single HTTP response.
      const MAX_COMPRESSED_BYTES = 100 * 1024 * 1024; // 100MB
      const MAX_DECOMPRESSED_BYTES = 1024 * 1024 * 1024; // 1GB
      const res = await this.httpClient.get<ArrayBuffer>(this.sourceUrl, {
        responseType: 'arraybuffer',
        timeout: 60000,
        maxContentLength: MAX_COMPRESSED_BYTES,
        maxBodyLength: MAX_COMPRESSED_BYTES,
      });
      const decompressed = zlib.gunzipSync(Buffer.from(res.data), { maxOutputLength: MAX_DECOMPRESSED_BYTES } as any).toString('utf-8');
      const lines = decompressed.split('\n');
      const rows: AsnTableRow[] = [];

      for (const line of lines) {
        if (!line) continue;
        // Columns: range_start  range_end  AS_number  country_code  AS_description
        const cols = line.split('\t');
        if (cols.length < 5) continue;
        const asn = parseInt(cols[2], 10);
        if (!asn || asn === 0) continue; // 0 = "not routed" placeholder rows
        const start = this.ipToNumber(cols[0]);
        const end = this.ipToNumber(cols[1]);
        if (start === null || end === null) continue;
        // Country code column: 'None'/'NONE' means unattributed - stored as ''.
        const cc = (cols[3] || '').trim().toUpperCase();
        rows.push({ start, end, asn, name: (cols[4] || '').trim(), country: cc === 'NONE' ? '' : cc });
      }

      rows.sort((a, b) => a.start - b.start);
      await this.store.replaceAsnTable(rows);
      this.applyRows(rows);
      this.loadedAt = Date.now();
      this.logger.info(`AsnIndex loaded: ${rows.length} ranges in ${Date.now() - started}ms (persisted for instant load on next restart)`);
    })().finally(() => {
      this.refreshing = null;
    });
    return this.refreshing;
  }

  private ipToNumber(ip: string): number | null {
    const parts = ip.trim().split('.');
    if (parts.length !== 4) return null;
    let n = 0;
    for (const p of parts) {
      const v = Number(p);
      if (!Number.isInteger(v) || v < 0 || v > 255) return null;
      n = (n << 8) + v;
    }
    return n >>> 0;
  }
}
