// src/services/ListUpdater.ts - with caching and incremental updates
import * as fs from 'fs';
import * as path from 'path';
import axios, { AxiosInstance } from 'axios';
import { Logger } from '../utils/Logger';
import { ListManager } from './ListManager';
import { RangeIndexStore } from './RangeIndexStore';
import { sharedKeepAliveHttpAgent, sharedKeepAliveHttpsAgent } from '../utils/HttpAgents';

interface ListSource {
  name: string;
  url: string;
  type: 'vpn' | 'datacenter' | 'hosting' | 'cdn' | 'tor' | 'proxy';
  enabled: boolean;
  etag?: string;
  lastModified?: string;
  lastHash?: string;
}

interface UpdateMetadata {
  last_update: string;
  total_ips: number;
  imported: number;
  skipped: number;
  sources_ok: number;
  sources_fail: number;
  duration_seconds: number;
  incremental: boolean;
}

// Per-source download result. `ips`/full string content is only ever
// populated when the source actually changed (see downloadListWithCache) -
// on an unchanged (304/hash-match) response there is nothing new to
// convert/store/write, so only the previously-recorded count is needed for
// logging. This is what lets ListUpdater avoid holding every source's full
// IP list in memory for the process lifetime (previously `sourceCache: Map
// <string, SourceCache>`, ~47MB on disk alone) - the DB-backed
// RangeIndexStore.list_source_cache table now holds only the hash + count
// needed for change detection, and the merged numeric ranges live in
// RangeIndexStore.list_ranges (see that file), not in an in-memory string
// array.
interface DownloadResult {
  ips: string[]; // only non-empty when changed === true
  ipCount: number;
  changed: boolean;
  newCount: number;
  notFound?: boolean;
}

// List updater - downloads and updates IP lists with caching - singleton pattern
export class ListUpdater {
  private static instance: ListUpdater;
  private logger: Logger;
  private listManager: ListManager;
  private updateInterval: NodeJS.Timeout | null = null;
  private dataDir: string;
  private listsDir: string;
  private isUpdating: boolean = false;
  private metadata: UpdateMetadata | null = null;
  // Bulk range storage/import bookkeeping - see RangeIndexStore.ts. Assigned
  // by init(), called once from index.ts's startup sequence before any
  // update runs.
  private rangeStore!: RangeIndexStore;
  // In-process mirror of RangeIndexStore's list_source_cache table,
  // populated once in init() (one bulk round trip instead of one round
  // trip per source) and kept in sync with every write this class makes -
  // it's the sole writer of that table, so this stays correct without
  // re-querying the DB on every single change-detection check or
  // getStats() call. See RangeIndexStore's getAllSourceCacheHashes() doc
  // comment for the same reasoning from the storage side.
  private sourceCache: Map<string, { hash: string; ipCount: number }> = new Map();
  // Shared keep-alive agents so the ~230 downloads below (mostly to
  // raw.githubusercontent.com) reuse TCP+TLS connections instead of paying
  // a fresh handshake per request - same pattern as IpChecker's httpClient.
  private httpClient: AxiosInstance;
  // Set true by abort() when the bot is shutting down. The download pool in
  // updateAllLists checks this between sources and stops handing out new work
  // the moment it's set, so a Ctrl-C in the middle of a ~300-source refresh
  // doesn't force the operator to wait for the whole run to finish before the
  // process can exit. Reset at the top of every updateAllLists so a later
  // scheduled/forced run isn't left permanently disabled.
  private aborted: boolean = false;
  // Whether to also write each source's IPs out as a plain-text file under
  // data/lists. On the file backend that export is the only human-readable
  // copy, so it's kept; on a DB backend (sqlite/mysql) the canonical data
  // already lives in RangeIndexStore, so these hundreds of per-refresh disk
  // writes are pure redundant I/O that only slow the refresh down - skipped.
  private persistListFiles: boolean = true;

  // Verified working list sources
  private sources: ListSource[] = [
    { name: 'X4BNet-VPN', url: 'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt', type: 'vpn', enabled: true },
    { name: 'X4BNet-Datacenter', url: 'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt', type: 'datacenter', enabled: true },
    { name: 'ScavengeR-VPN', url: 'https://raw.githubusercontent.com/Scav-engeR/vpn_list/main/output/vpn/ipv4.txt', type: 'vpn', enabled: true },
    { name: 'ScavengeR-Datacenter', url: 'https://raw.githubusercontent.com/Scav-engeR/vpn_list/main/output/datacenter/ipv4.txt', type: 'datacenter', enabled: true },
    { name: 'CDN-All', url: 'https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/main/all/all_plain_ipv4.txt', type: 'hosting', enabled: true },
    { name: 'CDN-Only', url: 'https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/main/cdn-only/cdn-only_plain_ipv4.txt', type: 'cdn', enabled: true },
    { name: 'IPSet-All', url: 'https://raw.githubusercontent.com/tn3w/IPSet/master/iplist.txt', type: 'vpn', enabled: true },
    { name: 'TOR-Exit-Nodes', url: 'https://check.torproject.org/torbulkexitlist', type: 'tor', enabled: true },
    // DISABLED (confirmed false-positive source) - see the detailed
    // rationale on the Socks4/Socks5 entries below, which applies equally
    // here: this is a scanner-generated open-proxy list, not a provider's
    // own address space, and it feeds the zero-corroboration Layer 0
    // static blacklist.
    { name: 'TheSpeedX-Proxy', url: 'https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt', type: 'proxy', enabled: false },
    { name: 'Datacenter-IPs', url: 'https://raw.githubusercontent.com/jhassine/server-ip-addresses/master/data/datacenters.txt', type: 'datacenter', enabled: true },
    // FireHOL's curated, minute-by-minute-updated aggregate of anonymizer
    // sources (Tor exits, open proxies, known VPN egress). This list is
    // scoped specifically to anonymizers, not general "attack" traffic, so
    // it adds real VPN/proxy/Tor recall without pulling in unrelated
    // abuse/malware IPs the way a generic threat feed would.
    { name: 'FireHOL-Anonymous', url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_anonymous.netset', type: 'proxy', enabled: true },
    // Per-ASN announced-prefix lists from ipverse/asn-ip, which mirrors the
    // public BGP routing table daily. Unlike ISP-name keyword matching,
    // ASN membership is a verifiable technical fact, not a guess: an IP
    // really is or isn't inside a given network's announced space. Each
    // ASN below has been individually confirmed (via bgp.tools/IPinfo) to
    // be a hosting/cloud/VPN-infrastructure network with no residential
    // subscriber base, to avoid ever pulling in a real consumer ISP's
    // address space. Add more only after verifying the same way.
    { name: 'ASN-DigitalOcean', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/14061/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Linode', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/63949/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Vultr', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/20473/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-OVH', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/16276/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Hetzner', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/24940/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-M247', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/9009/ipv4-aggregated.txt', type: 'vpn', enabled: true },
    { name: 'ASN-DatacampLimited', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/60068/ipv4-aggregated.txt', type: 'vpn', enabled: true },
    { name: 'ASN-Clouvider', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/62240/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-WorldStream', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/49981/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Cloudflare', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/13335/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-GoogleCloud', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/15169/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Microsoft', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/8075/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-SoftLayerIBM', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/36351/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-AmazonAWS', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/16509/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    // New ASNs matching the expanded VERIFIED_HOSTING_VPN_ASNS list in
    // ProviderLists.ts (same verification standard: confirmed pure
    // hosting/cloud/VPS networks, no residential subscriber base).
    { name: 'ASN-Scaleway', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/12876/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Contabo', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/51167/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-LeaseWebNL', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/16265/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-AlibabaCloud', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/45102/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-TencentCloud', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/132203/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-UpCloud', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/202053/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-ColoCrossing', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/36352/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-ReliableSite', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/23470/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-FranTechBuyVM', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/53667/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Sharktech', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/46844/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Psychz', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/40676/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Zenlayer', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/21859/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Selectel', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/49505/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-GTHost', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/53587/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-ServersCom', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/49453/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-DataPacket', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/395954/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    // Official, authoritative cloud-provider published IP ranges. These are
    // the providers' own documents (not a guess or a third-party mirror),
    // so false-positive risk is effectively zero - a residential player is
    // never inside AWS/GCP/Oracle's own published address space. The
    // existing line-parser already extracts CIDR-shaped substrings via
    // regex, which works fine against these JSON payloads too (each range
    // appears as a quoted "x.x.x.x/yy" string).
    { name: 'Official-AWS-Ranges', url: 'https://ip-ranges.amazonaws.com/ip-ranges.json', type: 'hosting', enabled: true },
    { name: 'Official-GCP-Cloud-Ranges', url: 'https://www.gstatic.com/ipranges/cloud.json', type: 'hosting', enabled: true },
    { name: 'Official-Google-Goog-Ranges', url: 'https://www.gstatic.com/ipranges/goog.json', type: 'hosting', enabled: true },
    { name: 'Official-OracleCloud-Ranges', url: 'https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json', type: 'hosting', enabled: true },
    // Additional official/first-party range publications (same
    // zero-guesswork rationale as the AWS/GCP/Oracle entries above: each
    // provider publishes its own address space, so there's no third-party
    // matching error possible).
    { name: 'Official-Cloudflare-Ranges', url: 'https://www.cloudflare.com/ips-v4', type: 'hosting', enabled: true },
    { name: 'Official-DigitalOcean-Ranges', url: 'https://digitalocean.com/geo/google.csv', type: 'hosting', enabled: true },
    { name: 'Official-Linode-Ranges', url: 'https://geoip.linode.com/', type: 'hosting', enabled: true },
    { name: 'Official-Fastly-Ranges', url: 'https://api.fastly.com/public-ip-list', type: 'cdn', enabled: true },
    // Microsoft doesn't publish a single stable direct-download URL for
    // Azure's ranges (the official page issues a new signed download link
    // every week), so this uses femueller/cloud-ip-ranges, a repo that
    // mirrors Microsoft's own published JSON and is refreshed regularly.
    { name: 'Mirror-Azure-Ranges', url: 'https://raw.githubusercontent.com/femueller/cloud-ip-ranges/master/microsoft-azure-ip-ranges.json', type: 'hosting', enabled: true },
    // TheSpeedX's companion SOCKS4/SOCKS5 lists from the same repo/author
    // already trusted for the HTTP proxy list above.
    //
    // DISABLED (confirmed false-positive source): unlike every other
    // source above, these three aren't a VPN/hosting company's own
    // address space - they're the output of a port scanner that
    // periodically rescans swaths of the internet for open SOCKS/HTTP
    // proxy ports and lists whatever answers. Those IPs are frequently
    // ordinary residential/business hosts with a port briefly open
    // (misconfigured router, IoT device, compromised host), and once the
    // scanner delists it the address is commonly reassigned by the ISP to
    // an unrelated, innocent customer before this project's next refresh
    // - the same "IP reuse" mechanism FireHOL's own docs call out as the
    // biggest false-positive source for this class of list
    // (https://iplists.firehol.org/). Worse, entries here land straight
    // in the Layer 0 static blacklist (ListManager.isBlacklisted): an
    // instant, unconditional, zero-corroboration ban, unlike every Layer 1
    // API check in IpChecker which requires 2 agreeing sources. Kept here
    // disabled for documentation; only re-enable paired with a
    // corroboration requirement instead of an instant static ban.
    { name: 'TheSpeedX-Proxy-Socks4', url: 'https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt', type: 'proxy', enabled: false },
    { name: 'TheSpeedX-Proxy-Socks5', url: 'https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt', type: 'proxy', enabled: false },

    // --- v8 expansion: per-ASN prefix downloads for every ASN in the
    // filtered brianhama/bad-asn-list import (see ProviderLists.ts
    // VERIFIED_HOSTING_VPN_ASNS for the full methodology/rationale). This
    // feeds the *bulk* CIDR blacklist (static index), giving defense in
    // depth alongside the live per-connection ASN-index check: even if a
    // player's IP is seen before the ASN index has that ASN loaded, it'll
    // already be present in the static blacklist file. Individual 404s
    // here (an ASN with no current announcement in ipverse's mirror) are
    // handled gracefully by downloadListWithCache and simply skipped.
    { name: 'ASN-TranquilHosting-3722', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/3722/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Ramnode-3842', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/3842/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-VpsDatacenter-6188', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/6188/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Leaseweb-7203', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/7203/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Servers-7979', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/7979/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Asn-8100', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/8100/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-LevantisHostingGmbh-8556', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/8556/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-EducationWebHosting-9823', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/9823/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-PowerbaseDatacenterServicesHkLtd-9925', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/9925/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-WebHostingProviderAndIspConnectivity-10200', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/10200/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-RackspaceHosting-10532', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/10532/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Netelligent-10929', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/10929/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-ManagedHostingServices-11230', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/11230/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Itron-11235', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/11235/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-SolidoHostingAS-12617', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/12617/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-AtomHostingSrl-13209', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/13209/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-TranquilHosting-13647', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/13647/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Datacenter-13739', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/13739/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-TechieHosting-13909', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/13909/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-ItHostingServices-14120', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/14120/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-PremiumHosting-14160', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/14160/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-NsiHosting-14244', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/14244/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-SpringsHosting-14567', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/14567/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-HostingSolutionLtd-14576', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/14576/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Amazon-14618', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/14618/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-WebhostChileSA-14708', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/14708/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-UltraHosting-14986', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/14986/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-RethemHostingLlc-14987', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/14987/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-CrystaltechWebHostingInc-14992', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/14992/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Rackspace-15395', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/15395/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-ColocallInternetDataCenterColocall-15497', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/15497/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-ServiciosDeHostingEnInternetSA-15919', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/15919/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-EquinixBrasilSp-16397', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/16397/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-KansasHosting-16862', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/16862/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-NetmagicDatacenterMumbai-17439', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/17439/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-InfoplexHostingAndManagedServiceProviderAsiaPacific-17669', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/17669/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-InetHostingInc-17881', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/17881/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-InfoplexHostingAndManagedServiceProviderAsiaPacific-17918', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/17918/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-UltraServeInternetPtyLtd-17920', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/17920/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Tm-17971', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/17971/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-GeminiSoftwareSolutionsPLtdHostingServices-18120', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/18120/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-BirdHostingInc-19133', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/19133/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-CanadaWebHosting-19234', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/19234/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Network-19871', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/19871/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Joesdatacenter-19969', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/19969/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Take2Hosting-20248', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/20248/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-TrojanHosting-20450', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/20450/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-NetgateDatacenterAsn-20692', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/20692/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-OcHosting-22152', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/22152/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-InmotionHosting-22611', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/22611/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-RackspaceHosting-22720', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/22720/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-QuantactHostingSolutions-23108', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/23108/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-SantaBarbaraWebHosting-23273', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/23273/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-UdomainWebHostingCompanyLtd-23881', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/23881/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-WebHostingAndColocationServices-24381', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/24381/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-PacificnetHostingLtd-24549', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/24549/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-InternetHostingServiceProviderToTheAditya-24558', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/24558/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-DatacenterLuxembourgSA-24611', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/24611/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-HostmasterLlc-24725', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/24725/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-DedipowerManagedHostingLimited-24931', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/24931/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-TheBunkerSecureHostingLimited-24958', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/24958/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-DsnetHostingLimited-25048', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/25048/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-LasVegasNvDatacenter-26277', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/26277/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-RebelHosting-26481', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/26481/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-CarpathiaHosting-26978', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/26978/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-BareMetalHosting-27223', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/27223/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-WebhostingNet-27229', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/27229/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-RackspaceHosting-27357', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/27357/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-SiteserverHosting-27597', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/27597/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-GigasHostingUsa-27640', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/27640/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-LocalDatacenterSolucoesEmComunicacaoLtda-28333', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/28333/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Leaseweb-28753', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/28753/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-GalacsysIsAnHostingAndManagedServicesProvider-28855', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/28855/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-NedcompHostingBV-28997', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/28997/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-HostmasterLlc-29067', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/29067/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-AutonomousSystemHostserverGmbh-29140', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/29140/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-HostingServicesInc-29302', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/29302/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Asp4AllHostingBV-29311', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/29311/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-ForsikringensDatacenterAS-29331', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/29331/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-SecuraHostingLtd-29452', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/29452/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-ReliableHostingServices-29713', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/29713/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-CarpathiaHosting-29748', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/29748/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Hvc-29802', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/29802/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-InternetHostingServers-29883', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/29883/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-BeyondHosting-30152', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/30152/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-As-30176', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/30176/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-TwinserversHostingSolutionsInc-30235', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/30235/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Leaseweb-30633', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/30633/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-JscHostingTelesystemsAutonomousSystem-31240', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/31240/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-BelowZeroHostingLtd-31659', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/31659/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-AsNumberForWebhostIeLtd-31698', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/31698/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-BluetowerHostingLlc-31981', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/31981/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Wii-32097', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/32097/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Asn-32181', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/32181/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Liquid-32244', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/32244/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-UnifiedWebhosting-32275', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/32275/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Singlehop-32475', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/32475/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-CrucialWebHosting-32647', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/32647/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-SliquaEnterpriseHosting-32740', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/32740/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Hostingservices-32780', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/32780/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-DedipowerManagedHosting-32911', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/32911/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Rackspace-33070', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/33070/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Dimenoc-33182', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/33182/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-NetworkDataCenterHost-33322', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/33322/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-FluidHostingLlc-33552', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/33552/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-OnlineSolutionsHostingServices-34541', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/34541/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-PeterhostRuHostingProviderAtSpb-35295', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/35295/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-DatacenterFryslanAs-35467', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/35467/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-CarpathiaHosting-35974', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/35974/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-PortlandInternetHostingLlc-36791', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/36791/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Hetzner-37153', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/37153/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-NewmediaExpressPteLtdSingaporeWebHostingServiceProvider-38001', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/38001/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Iomnet-38279', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/38279/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-ManagenetPtyLtdHostingServices-38894', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/38894/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-MelbourneServerHostingLtd-39451', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/39451/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Cj2HostingBV-39704', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/39704/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-DkHostmasterAS-39839', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/39839/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Turnkey-40244', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/40244/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-QwkNetHosting-40281', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/40281/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-HighDensityHosting-40374', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/40374/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-HostingConsulting-40539', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/40539/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-DatacenterBz-40715', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/40715/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-VpsDatacenter-40819', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/40819/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-DatacenterFinlandOy-41369', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/41369/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-DatacenterDOO-41427', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/41427/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Hosting-41665', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/41665/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-ModitDatacenterInformatikaiEsSzolgaltatoKft-42120', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/42120/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-HostingOperatorEserverRuLtd-42244', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/42244/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-HostingCenterLlc-42399', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/42399/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-AdacorHostingGmbh-42442', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/42442/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-TeknikIMediaDatacenterStockholmAb-42622', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/42622/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-CityNetworkHostingAb-42695', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/42695/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-AsManagedhostingDeGmbh-42699', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/42699/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-TaliaProvidesVsatNetworkAndHostingServicesWorldwide-42705', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/42705/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Ukservers-42831', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/42831/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-CertitHostingHandelsbolag-43021', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/43021/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-OutsourceryHostingLtd-43198', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/43198/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-SyanLimitedHosting-43620', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/43620/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-De-44066', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/44066/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-TdcHosting-44398', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/44398/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-BelcloudHostingCorporation-44901', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/44901/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-ZoneNetworksPtyLtd-45152', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/45152/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Rackspace-45187', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/45187/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-BluecentralPtyLtdHostingSolutions-45201', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/45201/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-DigitalSenseDataCentreHostingBrisbane-45481', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/45481/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-IndiagamesTransitAsContentHostingSerivceIndia-45693', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/45693/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Limestonenetworks-46475', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/46475/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Volumedrive-46664', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/46664/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-HostingCenterLtd-47385', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/47385/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-HostingSystemsLtd-47549', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/47549/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-PaulDavidHughesTradingAsHostingSystems-47625', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/47625/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-WeblandHostingAb-48093', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/48093/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-DatacenterNoordBv-48812', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/48812/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-HighAvailabilityHostingLimited-49485', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/49485/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-BestHostingCompanyLtd-49834', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/49834/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-24SolutionsHostingServicesAb-49949', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/49949/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-VenteloHostingAs-50608', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/50608/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-InfortelecomHosting-50926', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/50926/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Hostmaster-50968', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/50968/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-ExcellentHostingSwedenAb-50986', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/50986/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-IranPostCompany-51241', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/51241/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-HubaraHostingSolutionsSL-51294', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/51294/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-FideicomisoDeAdministracionDatacenterCapitalinas-52321', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/52321/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-ColombiaHosting-52335', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/52335/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-WnetInternetYHosting-52465', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/52465/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-DatacenterLtda-52674', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/52674/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-HostdimeComBrDataCenter-53055', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/53055/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-DatacenterEProvedoresLtda-53101', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/53101/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-InternetDatacenter-53221', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/53221/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Datacenter-53225', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/53225/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-ClearpathHosting-53281', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/53281/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-AllNineHosting-53342', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/53342/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Gorillaservers-53850', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/53850/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-GenesisHostingSolutions-53914', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/53914/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-RoyaHostingLlc-54334', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/54334/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-AstuteHostingInc-54527', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/54527/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Incero-54540', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/54540/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-InmotionHosting-54641', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/54641/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-AldenHostingLlc-54817', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/54817/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-PacketHost-54825', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/54825/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-WhiteSandsHosting-55229', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/55229/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-A2Hosting-55293', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/55293/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-GigabitHostingSdnBhd-55720', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/55720/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-ColocationHostingSdnBhd-55761', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/55761/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-DedicatedgamingComAu-56106', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/56106/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-SiaVpsHosting-56617', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/56617/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-JordensDatacenterNv-56799', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/56799/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-GigasHostingSA-57286', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/57286/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-DedipowerManagedHostingLimited-57669', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/57669/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Sfip84HostingUndMehrUgHaftungsbeschraenkt-57879', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/57879/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-LirDatacenterTelecomSrl-58113', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/58113/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-SmartnetHostingAndConnectivity-58667', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/58667/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-CarpathiaHosting-58797', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/58797/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-MicrochannelHostingPtyLtd-58922', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/58922/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-PtDapurHosting-59135', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/59135/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Lsw-59253', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/59253/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-DatacenterGroningenBV-59554', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/59554/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-CloudHostingLlc-59615', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/59615/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-PoboxHostingLimited-59705', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/59705/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-SecuritylayerHostingSolutionsSrl-59795', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/59795/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-TopLevelHostingSrl-59854', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/59854/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-MrgHostingBV-60476', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/60476/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-ServerCentreHostingLtd-60739', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/60739/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Leaseweb-60781', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/60781/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-NetwiseHostingLtd-60800', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/60800/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-ByHostingBV-61280', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/61280/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-PentaCorporateHostingLtd-62049', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/62049/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-ManagedhostingDeGmbh-62310', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/62310/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Digitalocean-62567', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/62567/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-RepriseHosting-62838', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/62838/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-ClarityWebHostingInc-62899', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/62899/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-AstuteHostingInc-63213', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/63213/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-RshHostingNetwork-63916', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/63916/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-ApcHostingPteLtd-132425', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/132425/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-DigiwebAdvancedHostingLimited-132509', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/132509/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-NxtgenDatacenterAndCloudTechnologiesPvtLtd-132717', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/132717/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Dedicated-132869', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/132869/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Lsw-133752', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/133752/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-OviHostingPvtLtd-135822', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/135822/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-DatacentaHostingLtd-196745', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/196745/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-CredocomHostingAps-196827', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/196827/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-NmaHostingSolutionsBv-197372', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/197372/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-ArkBHostingBv-197395', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/197395/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-SylonHostingGmbh-197439', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/197439/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-StockhoHostingSarl-197914', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/197914/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-UkWebhostingLtd-198047', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/198047/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-AsSeidorDatacenterSantander-198153', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/198153/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Game-198347', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/198347/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-CyberneticosHostingSl-198968', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/198968/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-VenzoHostingAS-199213', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/199213/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-K3HostingLimited-199481', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/199481/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Sorta-199847', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/199847/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-IpponHostingSarl-199997', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/199997/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-HostingUkraineLtd-200000', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/200000/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-HostingTechniquesLimited-200147', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/200147/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Ne-201597', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/201597/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-IngramMicroHostingBV-201634', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/201634/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-HandsHanseDatacenterServicesGmbh-201709', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/201709/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-AnslutenHostingISverigeAb-201983', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/201983/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-GoHostingSPRL-202118', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/202118/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-ServerHostingPtyLtd-206898', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/206898/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-InternetEWebHostingServDeInformaticaLtda-262603', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/262603/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-CentroDeTecnologiaArmazemDatacenterLtda-262978', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/262978/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-CenterHostingTecnologiaEireli-262990', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/262990/ipv4-aggregated.txt', type: 'hosting', enabled: true },
    { name: 'ASN-Leaseweb-394380', url: 'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/394380/ipv4-aggregated.txt', type: 'hosting', enabled: true },
  ];

  private constructor() {
    this.logger = Logger.getInstance();
    this.listManager = ListManager.getInstance();
    this.dataDir = path.join(process.cwd(), 'data');
    this.listsDir = path.join(this.dataDir, 'lists');

    if (!fs.existsSync(this.listsDir)) {
      fs.mkdirSync(this.listsDir, { recursive: true });
    }

    this.loadMetadata();

    this.httpClient = axios.create({
      httpAgent: sharedKeepAliveHttpAgent,
      httpsAgent: sharedKeepAliveHttpsAgent,
      headers: { 'User-Agent': 'WizanthiAntiVpn/2.0' },
    });
  }

  static getInstance(): ListUpdater {
    if (!ListUpdater.instance) {
      ListUpdater.instance = new ListUpdater();
    }
    return ListUpdater.instance;
  }

  // Must be called once (from index.ts's startup sequence) before any
  // update/rebuild runs. Also prunes any lingering DB rows for sources that
  // are no longer `enabled` here, so a source disabled in code doesn't keep
  // silently feeding stale ranges into the live static blacklist forever -
  // same reasoning rebuildStaticIndex's old in-memory filter documented.
  async init(rangeStore: RangeIndexStore, storageType?: string): Promise<void> {
    this.rangeStore = rangeStore;
    // Only the plain 'file' backend needs the human-readable data/lists/*.txt
    // export; on sqlite/mysql the ranges are already the canonical copy in
    // RangeIndexStore, so skip those redundant writes (see persistListFiles).
    this.persistListFiles = (storageType || 'file') === 'file';
    this.sourceCache = await rangeStore.getAllSourceCacheHashes();
    for (const source of this.sources) {
      if (!source.enabled) await this.rangeStore.replaceListRangesForSource(source.name, []);
    }
  }

  // Signals the in-flight updateAllLists (if any) to stop handing out new
  // downloads as soon as possible - called from the shutdown path so a
  // refresh that's mid-run can't hold the process open. stopAutoUpdate()
  // separately clears the recurring timer; this cancels the current pass.
  abort(): void {
    this.aborted = true;
  }

  private loadMetadata(): void {
    const metaPath = path.join(this.listsDir, 'update_metadata.json');
    if (fs.existsSync(metaPath)) {
      try {
        this.metadata = JSON.parse(fs.readFileSync(metaPath, 'utf-8'));
      } catch {}
    }
  }

  private saveMetadata(): void {
    const metaPath = path.join(this.listsDir, 'update_metadata.json');
    if (this.metadata) {
      // Compact (no pretty-print) - this is machine-owned state, not
      // something an operator needs to hand-read, so the extra CPU/bytes
      // spent indenting it buys nothing.
      fs.writeFileSync(metaPath, JSON.stringify(this.metadata), 'utf-8');
    }
  }

  private calculateHash(content: string): string {
    const crypto = require('crypto');
    return crypto.createHash('md5').update(content).digest('hex');
  }

  // --- IPv4 CIDR/IP -> numeric [start,end] range (deliberately not shared
  // with ListManager/DatasetLoader's equivalents - see DatasetLoader.ts's
  // own comment on why: keeps each file independently testable). ---
  private ipv4ToNumber(ip: string): number | null {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return null;
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  }

  private entryToRange(entry: string): [number, number] | null {
    if (entry.includes('/')) {
      const [range, bitsStr] = entry.split('/');
      const bits = parseInt(bitsStr, 10);
      if (isNaN(bits) || bits < 0 || bits > 32) return null;
      const base = this.ipv4ToNumber(range);
      if (base === null) return null;
      // Mask host bits off so a misaligned CIDR (e.g. 255.255.255.128/24)
      // yields its true network range instead of a shifted one that could
      // even wrap into an inverted end < start and corrupt the packed
      // RangeTable binary search. ListManager.ipInCIDR already masks; this
      // keeps the import path consistent with it.
      const mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
      const start = (base & mask) >>> 0;
      const size = bits === 0 ? 0x100000000 : Math.pow(2, 32 - bits);
      const end = (start + size - 1) >>> 0;
      return [start, end];
    }
    const num = this.ipv4ToNumber(entry);
    return num === null ? null : [num, num];
  }

  async startAutoUpdate(intervalHours: number = 6): Promise<void> {
    if (this.updateInterval) clearInterval(this.updateInterval);
    const intervalMs = intervalHours * 60 * 60 * 1000;

    this.updateInterval = setInterval(() => {
      this.updateAllLists(true).catch((err) => {
        this.logger.error('Scheduled list update failed', err);
      });
    }, intervalMs);
    
    this.logger.info(`Auto-update scheduled every ${intervalHours}h (incremental mode)`);
  }

  stopAutoUpdate(): void {
    if (this.updateInterval) {
      clearInterval(this.updateInterval);
      this.updateInterval = null;
    }
  }

  // Reloads ListManager's fast in-memory static index straight from
  // RangeIndexStore - this is the ONLY path that feeds curated bulk data
  // into lookups, and it never touches blacklist.json, so millions of
  // curated entries stay cheap to query and don't cause per-connection
  // disk writes. init() above already prunes disabled sources' rows out of
  // the DB, so this union is always exactly the currently-enabled set.
  private async rebuildStaticIndex(): Promise<void> {
    await this.listManager.loadStaticRangesFromStore(this.rangeStore);
  }

  async updateAllLists(incremental: boolean = true): Promise<UpdateMetadata> {
    if (this.isUpdating) {
      this.logger.info('Update already in progress, skipping');
      return this.metadata!;
    }
    
    this.isUpdating = true;
    try {
    const startTime = Date.now();
    
    const enabledSources = this.sources.filter(s => s.enabled);
    let totalIPs = 0;
    let imported = 0;
    let skipped = 0;
    let ok = 0;
    let fail = 0;
    let unchanged = 0;
    let notFoundCount = 0;

    this.aborted = false;
    this.logger.info(`Downloading from ${enabledSources.length} sources (incremental: ${incremental})...`);

    // Continuous worker pool instead of the old fixed-size batches. Batching
    // with a barrier made every group of N wait for its single slowest
    // member (one 45s-timeout source stalled the other 19 in its batch, plus
    // a flat inter-batch sleep on top) - so wall-clock was dominated by the
    // worst source in each batch, not the average. A pool of POOL_SIZE
    // workers each pulls the next source the instant it finishes its
    // previous one, so a slow source only ties up its own worker and the
    // remaining ~300 keep flowing at full width the whole time. These
    // sources are spread across dozens of independent hosts
    // (raw.githubusercontent.com, provider-specific domains, ...), not one
    // API that could rate-limit us, so there's no artificial delay to add.
    const POOL_SIZE = 32;

    // Per-source accounting, shared by every worker (all counters are `let`
    // in the enclosing scope). downloadListWithCache is self-contained per
    // source, so there's no shared mutable state between workers to guard.
    const recordResult = (result: PromiseSettledResult<DownloadResult>, source: ListSource): void => {
      if (result.status === 'fulfilled') {
        const { ipCount, changed, newCount, notFound } = result.value;

        if (notFound) {
          // Expected, permanent state for ASNs upstream has pruned (no
          // prefixes announced recently) - not a fetch failure, so don't
          // count it against sources_fail or spam the logs with a WARN
          // every single update cycle.
          notFoundCount++;
          if (ipCount > 0) {
            this.logger.debug(`  ${source.name}: No longer published upstream, using cached ${ipCount} IPs`);
          } else {
            this.logger.debug(`  ${source.name}: No data available (ASN has no announced prefixes)`);
          }
          return;
        }

        if (ipCount === 0) {
          fail++;
          this.logger.warn(`  ✗ ${source.name}: Empty response`);
          return;
        }

        if (!changed) {
          unchanged++;
          this.logger.info(`  ✓ ${source.name}: UNCHANGED (${ipCount} IPs, using cache)`);
          return;
        }

        totalIPs += ipCount;
        ok++;
        imported += newCount;
        skipped += ipCount - newCount;

        this.logger.info(`  ✓ ${source.name}: ${ipCount} IPs, +${newCount} new, ${ipCount - newCount} existing`);
      } else {
        fail++;
        // Surface the actual rejection reason (timeout, TLS, post-retry
        // 5xx, ...) instead of a bare "Failed" that hides why.
        this.logger.warn(`  ✗ ${source.name}: Failed`, (result as PromiseRejectedResult).reason);
      }
    };

    let cursor = 0;
    const worker = async (): Promise<void> => {
      while (true) {
        // Stop pulling new work the moment shutdown is requested - whatever's
        // already downloaded stays imported; the rest is simply skipped.
        if (this.aborted) return;
        const idx = cursor++;
        if (idx >= enabledSources.length) return;
        const source = enabledSources[idx];
        try {
          const value = await this.downloadListWithCache(source, incremental);
          recordResult({ status: 'fulfilled', value }, source);
        } catch (reason) {
          recordResult({ status: 'rejected', reason }, source);
        }
      }
    };

    await Promise.all(
      Array.from({ length: Math.min(POOL_SIZE, enabledSources.length) }, () => worker())
    );

    const duration = (Date.now() - startTime) / 1000;
    
    this.metadata = {
      last_update: new Date().toISOString(),
      total_ips: totalIPs,
      imported,
      skipped,
      sources_ok: ok,
      sources_fail: fail,
      duration_seconds: duration,
      incremental
    };
    
    this.saveMetadata();
    await this.rebuildStaticIndex();

    this.logger.info(`Update complete: ${totalIPs} IPs, +${imported} new, ${skipped} dup, ${ok}/${enabledSources.length} ok, ${unchanged} unchanged, ${notFoundCount} not-found (upstream pruned), ${fail} fail (${duration}s)`);

    return this.metadata;
    } finally {
      this.isUpdating = false;
    }
  }

  private async downloadListWithCache(source: ListSource, incremental: boolean, attempt: number = 1): Promise<DownloadResult> {
    const maxAttempts = 2;
    const timeoutMs = attempt === 1 ? 45000 : 90000;

    try {
      const response = await this.httpClient.get(source.url, {
        timeout: timeoutMs,
        responseType: 'text',
        headers: {
          // Conditional-request headers only in incremental mode. A forced
          // full update (incremental === false) must re-fetch and re-import
          // regardless of ETag/Last-Modified - sending these would let the
          // server answer 304 and skip the re-import the caller explicitly
          // asked for.
          ...(incremental && source.etag && { 'If-None-Match': source.etag }),
          ...(incremental && source.lastModified && { 'If-Modified-Since': source.lastModified })
        },
        validateStatus: (status) => status < 500,
        // These run against ~300 pre-approved, but still third-party, URLs
        // fetched in concurrent batches of 20 (see updateAllLists above) -
        // without a cap, one compromised/hijacked source returning an
        // oversized body could balloon memory across a whole batch at once.
        // 200MB comfortably covers every legitimate bulk list this project
        // downloads today.
        maxContentLength: 200 * 1024 * 1024,
        maxBodyLength: 200 * 1024 * 1024,
      });

      // Check if content not modified (304) - only the hash/count need to
      // be remembered for an unchanged source, not its full IP list (see
      // the DownloadResult comment above), so this only ever reads from
      // RangeIndexStore's small list_source_cache table.
      if (response.status === 304) {
        const cached = this.sourceCache.get(source.name);
        if (cached) {
          this.logger.debug(`  ${source.name}: Not modified, using cache`);
          return { ips: [], ipCount: cached.ipCount, changed: false, newCount: 0 };
        }
        // 304 but no cached row to fall back on (etag/DB out of sync). Do NOT
        // fall through: the 304 body is empty, and parsing it would call
        // replaceListRangesForSource(name, []) and wipe this source's ranges.
        // Treat it as "unchanged, nothing to do" instead.
        this.logger.debug(`  ${source.name}: 304 with no cache row, leaving existing data intact`);
        return { ips: [], ipCount: 0, changed: false, newCount: 0 };
      }

      if (response.status === 404) {
        // A 404 here almost always means the upstream (e.g. ipverse's
        // as-ip-blocks) has pruned this ASN's directory because it hasn't
        // announced any prefixes in a while - not a transient fetch problem.
        // If we still have a cached copy, keep reporting it as present
        // instead of silently collapsing to an empty list every run. Either
        // way this is a "not found" outcome, distinct from a source that
        // responded successfully but with zero parseable IPs (a real red
        // flag) - the underlying DB rows for this source are left as-is
        // either way (nothing to replace them with).
        const cached = this.sourceCache.get(source.name);
        if (cached && cached.ipCount > 0) {
          return { ips: [], ipCount: cached.ipCount, changed: false, newCount: 0, notFound: true };
        }
        return { ips: [], ipCount: 0, changed: false, newCount: 0, notFound: true };
      }

      // Any other non-2xx status (403/408/429 rate-limit, 400, ...) got past
      // validateStatus (which only lets us handle 304/404 in-code above) but
      // is NOT a valid list body. Falling through to parse it would (a) find
      // zero IPs in the error/rate-limit page and report a misleading "Empty
      // response", and (b) call replaceListRangesForSource(name, []) - wiping
      // this source's previously-good ranges over what's usually a transient
      // GitHub-raw 429 from fetching ~300 URLs in concurrent batches. Throw
      // instead so the retry/backoff path handles it and, once attempts are
      // exhausted, it's counted as a failure with the existing data intact.
      if (response.status < 200 || response.status >= 300) {
        throw new Error(`HTTP ${response.status}`);
      }

      // Update ETag and Last-Modified for next time
      const etag = response.headers['etag'];
      const lastModified = response.headers['last-modified'];
      if (etag) source.etag = etag;
      if (lastModified) source.lastModified = lastModified;

      const lines = (response.data as string).split('\n');
      const ips: string[] = [];
      const ipRegex = /(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?/;

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//')) continue;
        const match = trimmed.match(ipRegex);
        if (match) ips.push(match[0]);
      }

      const uniqueIps = [...new Set(ips)];
      const newHash = this.calculateHash(uniqueIps.join('\n'));

      // Check if content actually changed - hash comparison against the DB-
      // stored hash (not a full IP-array comparison), so an unchanged
      // source costs one small indexed lookup, no matter how large it is.
      const cached = this.sourceCache.get(source.name);
      if (cached && cached.hash === newHash && incremental) {
        this.logger.debug(`  ${source.name}: Content unchanged (hash match), using cache`);
        return { ips: [], ipCount: cached.ipCount, changed: false, newCount: 0 };
      }

      // "New" count is an approximation (count delta vs the previous run),
      // not an exact per-IP diff - purely informational logging, and this
      // avoids needing to keep the previous run's full IP array in memory
      // just to compute a set difference.
      const previousCount = cached?.ipCount ?? 0;
      const newCount = Math.max(0, uniqueIps.length - previousCount);

      // Convert to numeric ranges and persist - one transaction, prepared
      // statements, replaces this source's old rows atomically (see
      // RangeIndexStore.replaceListRangesForSource). This is the DB write
      // that used to be "keep the whole IP array in a Map forever".
      const ranges: Array<[number, number]> = [];
      for (const entry of uniqueIps) {
        const r = this.entryToRange(entry);
        if (r) ranges.push(r);
      }
      await this.rangeStore.replaceListRangesForSource(source.name, ranges);
      await this.rangeStore.setSourceCacheHash(source.name, newHash, uniqueIps.length);
      this.sourceCache.set(source.name, { hash: newHash, ipCount: uniqueIps.length });
      this.saveListToFile(source.name, uniqueIps);

      return { ips: uniqueIps, ipCount: uniqueIps.length, changed: true, newCount };

    } catch (error: any) {
      if (attempt < maxAttempts) {
        this.logger.warn(`  Retry ${source.name} (${attempt}/${maxAttempts})`);
        await this.delay(2000);
        return this.downloadListWithCache(source, incremental, attempt + 1);
      }
      throw error;
    }
  }

  private saveListToFile(name: string, ips: string[]): void {
    // Skip entirely on DB backends - the canonical ranges are already in
    // RangeIndexStore, so this export would be pure redundant disk I/O
    // (hundreds of writes per refresh) that only slows the refresh down.
    if (!this.persistListFiles) return;
    const filename = name.toLowerCase().replace(/[^a-z0-9]/g, '_') + '.txt';
    const filepath = path.join(this.listsDir, filename);
    // Fire-and-forget async write instead of writeFileSync: this runs once
    // per source per update cycle (hundreds of times), and a synchronous
    // write blocks the whole Node event loop - including in-flight player
    // connection checks - for however long that write takes. The async
    // version lets those keep running while the write completes in the
    // background; any failure is logged rather than silently dropped.
    // Purely a human-readable export at this point - the canonical data
    // lives in RangeIndexStore.
    fs.writeFile(filepath, ips.join('\n'), 'utf-8', (err) => {
      if (err) this.logger.warn(`Failed to write list file ${filename}`, err);
    });
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Force full update (ignore cache)
  async forceFullUpdate(): Promise<UpdateMetadata> {
    this.logger.info('Forcing full update (ignoring cache)...');
    return this.updateAllLists(false);
  }

  getStats(): { total_sources: number; enabled_sources: number; is_updating: boolean; total_ips?: number; lists_dir: string; cached_sources: number } {
    const cachedSources = this.sources.filter(s => s.enabled && this.sourceCache.has(s.name)).length;
    return {
      total_sources: this.sources.length,
      enabled_sources: this.sources.filter(s => s.enabled).length,
      is_updating: this.isUpdating,
      total_ips: this.metadata?.total_ips,
      lists_dir: this.listsDir,
      cached_sources: cachedSources,
    };
  }

  getMetadata(): UpdateMetadata | null {
    return this.metadata;
  }
}
