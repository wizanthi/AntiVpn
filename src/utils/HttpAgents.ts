// src/utils/HttpAgents.ts
//
// Process-wide shared keep-alive HTTP/HTTPS agents, used by every outbound
// client in this project that talks to third-party IP-intelligence APIs on
// the per-connection hot path (NetworkAgeService, ResidentialProxyDetector,
// ReverseDnsService, IpChecker's own Layer 1 battery). Reusing one pair of
// agents (instead of each service constructing its own) means every one of
// those clients pools TCP+TLS connections against the *same* keep-alive
// socket set - so if two services happen to call the same host in quick
// succession, the second one can reuse a warm connection the first one
// opened, not just its own.
//
// A custom `lookup` is passed to both agents so repeated DNS resolution for
// the same hostname (common during the startup fan-out across ~15 API
// hosts, and across the many github.com-adjacent list-source hosts in
// ListUpdater) is served from an in-process cache instead of re-querying
// the OS resolver on every single connection - Node's default dns.lookup
// has no caching of its own.
import * as http from 'http';
import * as https from 'https';
import * as dns from 'dns';

interface DnsCacheEntry {
  address: string;
  family: number;
  expiresAt: number;
}

interface DnsCacheAllEntry {
  addresses: dns.LookupAddress[];
  expiresAt: number;
}

const DNS_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes - long enough to matter, short enough to respect DNS changes
const dnsCache = new Map<string, DnsCacheEntry>();
// Separate cache for `{ all: true }` lookups - Node's Happy Eyeballs / autoSelectFamily
// connection logic (on by default since Node 20) resolves via this shape, expecting
// callback(err, addresses[]) instead of callback(err, address, family). Conflating the
// two previously made every connection using these agents fail with
// "ERR_INVALID_IP_ADDRESS: Invalid IP address: undefined", since a single {address,family}
// callback was returned where Node expected an array to iterate.
const dnsCacheAll = new Map<string, DnsCacheAllEntry>();

function cachingLookup(
  hostname: string,
  options: dns.LookupAllOptions | dns.LookupOneOptions | ((err: NodeJS.ErrnoException | null, address: string | dns.LookupAddress[], family?: number) => void),
  callback?: (err: NodeJS.ErrnoException | null, address: string | dns.LookupAddress[], family?: number) => void
): void {
  const cb = (typeof options === 'function' ? options : callback!) as (err: NodeJS.ErrnoException | null, address: any, family?: number) => void;
  const opts = typeof options === 'function' ? undefined : options;
  // Include the requested address family in the cache key (and forward it to
  // dns.lookup): a lookup pinned to IPv4 vs IPv6 must not be served a cached
  // address of the other family resolved under a different request.
  const family = (opts && (opts as dns.LookupOneOptions).family) || 0;

  if (opts && (opts as dns.LookupAllOptions).all) {
    const key = `${hostname}|all|${family}`;
    const cached = dnsCacheAll.get(key);
    if (cached && cached.expiresAt > Date.now()) {
      cb(null, cached.addresses);
      return;
    }
    dns.lookup(hostname, { all: true, family }, (err, addresses) => {
      if (!err) dnsCacheAll.set(key, { addresses, expiresAt: Date.now() + DNS_CACHE_TTL_MS });
      cb(err, addresses);
    });
    return;
  }

  const key = `${hostname}|${family}`;
  const cached = dnsCache.get(key);
  if (cached && cached.expiresAt > Date.now()) {
    cb(null, cached.address, cached.family);
    return;
  }
  dns.lookup(hostname, { family }, (err, address, fam) => {
    if (!err) dnsCache.set(key, { address, family: fam, expiresAt: Date.now() + DNS_CACHE_TTL_MS });
    cb(err, address, fam);
  });
}

export const sharedKeepAliveHttpAgent = new http.Agent({ keepAlive: true, maxSockets: 64, lookup: cachingLookup as any });
export const sharedKeepAliveHttpsAgent = new https.Agent({ keepAlive: true, maxSockets: 64, lookup: cachingLookup as any });
