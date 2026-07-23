// src/services/ProviderLists.ts
//
// v2 — trimmed after a false-positive audit.
//
// The keyword lists are matched with a simple substring check against an
// ISP/organization name. Specific brand and company names are safe to match
// this way. Bare generic words are not: many legitimate residential,
// mobile, and business ISPs use generic industry terms ("cloud", "server",
// "hosting", "infrastructure", "proxy", "anonymous", "ixp"...) somewhere in
// their registered org string without being a VPN/proxy/hosting provider at
// all. Matching those bare words banned real players.
//
// Removed from this version: bare single words and generic multi-word
// phrases that describe broad internet-infrastructure concepts (transit,
// IXPs, load balancing, edge computing, database/storage hosting, generic
// "cloud"/"hosting"/"server"/"proxy"/"anonymous") rather than naming an
// actual VPN, proxy, or hosting company. Specific company/product names are
// kept as-is.

export const VPN_KEYWORDS: string[] = [
    'nordvpn', 'nord vpn', 'nordsec', 'nord security',
    'expressvpn', 'express vpn', 'express technologies',
    'surfshark', 'surfshark vpn', 'surfshark ltd',
    'cyberghost', 'cyber ghost', 'cyberghost srl',
    'private internet access', 'pia vpn',
    'protonvpn', 'proton vpn', 'proton ag', 'proton technologies',
    'mullvad', 'mullvad vpn', 'mullvad vpn ab',
    'windscribe', 'windscribe limited',
    'hidemyass', 'hide my ass', 'hma vpn',
    'tunnelbear', 'tunnel bear',
    'hotspot shield', 'hotspotshield',
    'ipvanish', 'ip vanish',
    'vyprvpn', 'vypr vpn',
    'zenmate', 'zen mate',
    'betternet', 'better net',
    'psiphon', 'psiphon inc',
    'purevpn', 'pure vpn',
    'privatevpn', 'private vpn',
    'trust zone', 'trust.zone',
    'airvpn', 'air vpn',
    'azirevpn', 'azire vpn',
    'hide me', 'hide.me',
    'ivpn', 'ivpn limited',
    'ovpn', 'ovpn ab',
    'strongvpn', 'strong vpn',
    'torguard', 'tor guard',
    'vpn unlimited', 'keepsolid',
    'speedify', 'speedify inc',
    'ibvpn', 'nvpn', 'slickvpn',
    'seed4.me', 'seed4me',
    'vpnsecure', 'vpn secure',
    'ironsocket', 'iron socket',
    'cactusvpn', 'cactus vpn',
    'blackvpn', 'black vpn',
    'cryptostorm', 'crypto storm',
    'perfect privacy', 'perfect-privacy',
    'privado', 'privadovpn',
    'atlas vpn', 'atlasvpn',
    'urban vpn', 'urbanvpn',
    'hola vpn', 'holavpn',
    'touch vpn', 'touchvpn',
    'browsec', 'browsec vpn',
    'setupvpn', 'setup vpn',
    'turbo vpn', 'turbovpn',
    'snap vpn', 'snapvpn',
    'thunder vpn', 'thundervpn',
    'flash vpn', 'flashvpn',
    'ultra vpn', 'ultravpn',
    'vpn hub', 'vpnhub',
    'vpn gate', 'vpngate',
    'vpn book', 'vpnbook',
    'vpn monster', 'vpnmonster',
    'vpn robot', 'vpnrobot',
    'x vpn', 'xvpn',
    'safervpn', 'safer vpn',
    'goose vpn', 'goosevpn',
    'boxpn', 'box pn',
    'faceless.me', 'faceless me',
    'softether vpn',
    'openvpn inc',
    'vpnhero', 'vpn hero',
    'finevpn', 'fine vpn',
    'ivacy', 'ivacy vpn',
    'getflix', 'getflix vpn',
    'unlocator', 'unlocator vpn',
    'switchvpn', 'switch vpn',
    'proxy.sh',
    'monstervpn', 'monster vpn',
    'smartdnsproxy', 'smart dns proxy',
    // --- Added: more consumer/antivirus-bundled VPN brands (same
    // brand-name-only standard as the rest of this list) ---
    'avast secureline', 'secureline vpn',
    'avg secure vpn',
    'norton secure vpn', 'norton wifi privacy',
    'mcafee safe connect',
    'kaspersky vpn secure connection', 'kaspersky secure connection',
    'bitdefender vpn', 'bitdefender premium vpn',
    'f-secure freedome', 'freedome vpn',
    'totalav vpn', 'total av vpn',
    'malwarebytes privacy',
    'opera vpn', 'opera browser vpn',
    'google one vpn', 'warp+ vpn',
    'ufo vpn', 'ufovpn',
    'pandavpn', 'panda vpn',
    'whoer vpn', 'whoervpn',
    'astrill vpn', 'astrillvpn',
    'vpn.ht',
    'le vpn', 'levpn',
    'zoogvpn', 'zoog vpn',
    'anonine vpn', 'anonine',
    'shellfire vpn',
    'encrypt.me', 'encrypt me vpn',
    'vpn360', 'vpn 360',
    'kaspersky vpn',
    'vpn defender', 'defendervpn',
    'wachee vpn',
    'unblockvpn', 'unblock vpn',
    'supervpn', 'super vpn',
    'yoga vpn',
    'sky vpn', 'skyvpn',
    'hexatech vpn', 'hexatech',
    'proton vpn free',
];
export const DATACENTER_KEYWORDS: string[] = [
    'equinix', 'equinix inc',
    'digital realty', 'digital realty trust',
    'cyrusone', 'cyrusone inc',
    'coresite', 'coresite realty',
    'interxion', 'interxion digital',
    'datacamp', 'datacamp limited',
    'datapacket', 'datapacket limited',
    'm247', 'm247 europe', 'm247 limited',
    'ddos-guard', 'ddos-guard llc',
    'qrator', 'qrator labs',
    'serverius', 'serverius b.v.',
    'webtropia', 'webtropia gmbh',
    'myracloud', 'myracloud gmbh',
    'reliablesite', 'reliablesite llc',
    'webnx', 'webnx inc',
    'multacom', 'multacom corporation',
    'sentris network',
    'secured servers', 'secured servers llc',
    'ioflood', 'ioflood llc',
    'hivelocity', 'hivelocity inc',
    'constant.com', 'constant company',
    'steadfast networks',
    'handy networks', 'handy networks llc',
    'performive', 'performive llc',
    'onlyservers', 'onlyservers llc',
    'server house llc',
    'uk servers ltd',
    'internet utilities na llc',
    'latitude.sh', 'latitude sh', 'cherry servers',
    'datashack', 'datashack llc', 'cherry server',
    'colohouse', 'colohouse com',
    'coloserv', 'coloserv com',
    'gigenet', 'gigenet com',
    'globalfrag', 'globalfrag com',
    'flexential', 'flexential com',
    'evocative', 'evocative com',
    'drserver', 'drserver net',
    'quickpacket', 'quickpacket com',
    'dosarrest', 'dosarrest com',
    'server farm', 'server cluster', 'server room',
    'colocation facility', 'colo facility',
    'rack space', 'server rack',
    'edge data center facility',
    'modular data center', 'container data center',
    // --- Added: more named colocation/datacenter operators ---
    'ntt global data centers', 'ntt data centers',
    'rackspace', 'rackspace technology',
    'cyxtera', 'cyxtera technologies',
    'qts realty', 'qts data centers',
    'iron mountain data centers',
    'switch inc', 'switch datacenters',
    'vantage data centers',
    'nextdc', 'nextdc limited',
    'global switch',
    't5 data centers',
    'yondr group',
    'compass datacenters',
    'aligned data centers',
    'evoque data center solutions',
    'colovore', 'colovore llc',
    'databank', 'databank holdings',
    'sabey data centers',
    'stack infrastructure',
    'chindata group',
    'gds services', 'gds holdings',
    'st telemedia global data centres',
    'princeton digital group',
    'bridge data centres',
];
export const PROXY_KEYWORDS: string[] = [
    'brightdata', 'bright data', 'luminati', 'luminati networks',
    'oxylabs', 'oxylabs proxy',
    'smartproxy', 'smart proxy',
    'geosurf', 'geosurf proxy',
    'netnut', 'netnut proxy',
    'soax', 'soax proxy',
    'iproyal', 'ip royal',
    'webshare', 'web share',
    'stormproxies', 'storm proxies',
    'myprivateproxy', 'my private proxy',
    'instantproxies', 'instant proxies',
    'sslprivateproxy', 'ssl private proxy',
    'highproxies', 'high proxies',
    'proxy-cheap', 'proxy cheap',
    'proxy-seller', 'proxy seller',
    'proxy-sale', 'proxy sale',
    'proxystore', 'proxy store',
    'marsproxies', 'mars proxies',
    'proxyrack', 'proxy rack',
    'rayobyte', 'rayobyte proxy',
    'dataimpulse', 'data impulse',
    'infatica', 'infatica proxy',
    'proxyempire', 'proxy empire',
    'mangoproxy', 'mango proxy',
    'ipnproxy', 'ipn proxy',
    'geonode', 'geonode proxy',
    'the social proxy', 'social proxy',
    'proxycompass', 'proxy compass',
    'nstproxy', 'nst proxy',
    'lumiproxy', 'lumi proxy',
    'proxyblocks', 'proxy blocks',
    'proxidize', 'proxidize proxy',
    'roundproxies', 'round proxies',
    'proxywing', 'proxy wing',
    'swiftproxy', 'swift proxy',
    'lightning proxies', 'lightning proxy',
    'shadowsocks', 'shadowsocks proxy',
    'v2ray proxy', 'v2fly',
    'trojan-gfw',
    'xray-core',
    'vmess proxy', 'vless proxy',
    'hysteria proxy',
    'naiveproxy', 'naive proxy',
    'sing-box', 'singbox',
    'anonymous-proxy',
    'free-proxy', 'freeproxy',
    'open proxy list', 'free proxy list', 'proxylist',
    'sneaker proxy',
    'proxy scraping service',
    // --- Added: more residential/datacenter proxy-network brands ---
    '922 s5 proxy', '922proxy', '922 proxy',
    'piaproxy', 'pia proxy',
    'froxy', 'froxy proxy',
    'asocks', 'asocks proxy',
    'proxyrotator', 'proxy rotator',
    'ipidea', 'ipidea proxy',
    'lunaproxy', 'luna proxy',
    'pyproxy',
    'ipfoxy', 'ip foxy',
    'kookeey', 'kookeey proxy',
    'nimbleway', 'nimble proxies',
    'massive proxies', 'massiveproxies',
    'proxy-n-vpn', 'proxynvpn',
    'proxyline', 'proxy line',
    'rola ip', 'rolaip',
    'crawlera proxy', 'zyte proxy',
    'apify proxy',
    'blazing seo', 'blazingseo proxy',
    'petabyte proxy',
    'privateproxy.me',
    'squid proxy service', 'squid proxy provider',
];
export const HOSTING_KEYWORDS: string[] = [
    'digitalocean', 'digital ocean', 'digitalocean llc',
    'amazon web services', 'amazon aws', 'amazon data',
    'microsoft azure', 'azure cloud',
    'google cloud platform', 'gcp',
    'oracle cloud',
    'alibaba cloud',
    'tencent cloud',
    'ibm cloud', 'softlayer',
    'baidu cloud',
    'huawei cloud',
    'akamai connected cloud',
    'cloudflare warp',
    'fastly inc',
    'linode', 'linode llc',
    'vultr', 'vultr holdings', 'vultr holdings llc',
    'ovh sas', 'ovh hosting', 'ovhcloud',
    'hetzner', 'hetzner online', 'hetzner online gmbh',
    'choopa', 'choopa llc',
    'colocrossing', 'colocrossing solutions',
    'buyvm', 'buyvm llc',
    'ramnode', 'ramnode llc',
    'psychz', 'psychz networks',
    'quadranet', 'quadranet enterprises',
    'phoenixnap', 'phoenix nap',
    'leaseweb', 'leaseweb global',
    'online.net', 'online sas',
    'scaleway', 'scaleway sas',
    'contabo', 'contabo gmbh',
    'netcup', 'netcup gmbh',
    'ionos se', '1&1 ionos',
    'hostwinds', 'hostwinds llc',
    'namecheap hosting',
    'godaddy hosting',
    'bluehost', 'bluehost inc',
    'hostgator', 'hostgator com',
    'siteground', 'siteground hosting',
    'dreamhost', 'dreamhost llc',
    'hostinger', 'hostinger international',
    'liquid web', 'liquid web llc',
    'wpengine', 'wp engine',
    'a2 hosting', 'a2 hosting inc',
    'greengeeks', 'greengeeks llc',
    'inmotion hosting', 'inmotion hosting inc',
    'aruba cloud',
    'krystal hosting',
    'interserver', 'interserver inc',
    'hostpapa', 'hostpapa inc',
    'hostodo', 'hostodo com',
    'hostus', 'hostus com',
    'hosteons', 'hosteons com',
    'hostnamaste', 'hostnamaste com',
    'hostcram', 'hostcram com',
    'hostdare', 'hostdare com',
    'hostkoala', 'hostkoala com',
    'hostarmada', 'hostarmada com',
    'hostdime', 'hostdime com',
    'hosthavoc', 'hosthavoc com',
    'hostkey', 'hostkey b.v.',
    'hosthatch', 'hosthatch inc',
    'nexusbytes', 'nexusbytes llc',
    'servarica', 'servarica inc',
    'liteserver', 'liteserver nl',
    'greencloud', 'greencloud llc',
    'anynode', 'anynode llc',
    'servercheap', 'servercheap inc',
    'cloudcone', 'cloudcone llc',
    'evolution hosting', 'evolution hosting llc',
    'maxkvm', 'maxkvm llc',
    'racknerd', 'racknerd llc',
    'melbicom', 'melbicom llc',
    'serverhino', 'serverhino llc',
    'vdsina', 'vdsina llc',
    'firstvds', 'firstvds llc',
    'ruvds', 'ruvds llc',
    'aeza', 'aeza group', 'aeza international',
    'timeweb cloud',
    'beget', 'beget llc',
    'sprinthost', 'sprinthost llc',
    'reg.ru', 'reg.ru ltd',
    'nic.ru', 'nic.ru jsc',
    'masterhost', 'masterhost llc',
    'spaceweb', 'spaceweb llc',
    'webdock', 'webdock cloud',
    'dataforest', 'dataforest gmbh',
    'alexhost', 'alexhost srl',
    'axushost', 'axushost b.v.',
    'pq hosting', 'pqhosting',
    'it-grad', 'it grad',
    'fornex', 'fornex com',
    'vscale', 'vscale io',
    'king-servers', 'king servers',
    'cdn77', 'cdn77 com',
    'stackpath', 'stackpath llc',
    'keycdn', 'keycdn llc',
    'bunnycdn', 'bunnycdn llc',
    'amazon cloudfront',
    'vercel', 'vercel inc',
    'netlify', 'netlify inc',
    'fly.io',
    'railway corp',
    'edgecast networks',
    'limelight networks',
    'chinacache networks',
    'wangsu science',
    'quantil networks',
    'dedicated server hosting',
    'bare metal server',
    'colocation hosting',
    'wordpress hosting', 'email hosting', 'dns hosting',
    // --- Added: more VPS/cloud/CDN brands ---
    'sharktech', 'shark tech hosting',
    'psychz networks',
    'g-core labs', 'gcore',
    'zenlayer', 'zenlayer inc',
    'selectel', 'selectel ltd',
    'gthost', 'gt host',
    'servers.com',
    'datapacket', 'data packet llc',
    'kamatera', 'kamatera inc',
    'cloudsigma', 'cloudsigma ag',
    'exoscale', 'exoscale sa',
    'time4vps', 'time4vps eu',
    'serverspace', 'serverspace io',
    'vdsina',
    'g-portal', 'gportal gmbh',
    'nitrado', 'nitrado gmbh',
    'shockhosting', 'shock hosting',
    'crownnetworks', 'crown networks',
    'zappie host', 'zappiehost',
    'hostslim', 'hostslim nl',
    'ssd nodes', 'ssdnodes',
    'kimsufi', 'so you start',
    'upcloud ltd',
    'gandi.net hosting',
    'combell', 'combell nv',
    'one.com hosting',
    'strato ag hosting',
    'df hosting',
    'iweb technologies',
    'cogeco peer 1',
    'datacenter.com',
];
export const TRUSTED_PROVIDERS: string[] = [
    'kyivstar', 'kievstar',
    'vodafone ukraine', 'vodafone ua',
    'lifecell', 'lifecell ukraine',
    'ukrtelecom', 'jsc ukrtelecom',
    'lanet', 'lanet network',
    'triolan', 'triolan ukraine',
    'deutsche telekom', 'deutsche telekom ag', 'telekom deutschland',
    'vodafone germany', 'vodafone de',
    'vodafone uk', 'vodafone italy', 'vodafone spain',
    'vodafone portugal', 'vodafone turkey', 'vodafone egypt',
    'orange', 'orange france', 'orange poland',
    'orange spain', 'orange belgium', 'orange moldova',
    'orange egypt', 'orange morocco',
    'sfr', 'sfr sa',
    'bouygues', 'bouygues telecom',
    'free mobile', 'free sas', 'free mobile sas',
    'telefonica', 'movistar', 'o2 germany',
    'telenor', 'telenor as', 'telenor norge', 'telenor sweden',
    'telia', 'telia company', 'telia sweden',
    'telia finland', 'telia norway',
    'elisa', 'elisa oyj', 'elisa finland',
    'dna', 'dna oy', 'dna finland',
    'swisscom', 'swisscom ag',
    'proximus', 'proximus nv',
    'kpn', 'kpn b.v.', 'kpn telecom',
    'bt group', 'bt plc', 'british telecom',
    'ee limited', 'ee uk',
    'sky uk', 'sky broadband',
    'virgin media', 'virgin media uk',
    'talktalk', 'talktalk telecom',
    'plusnet', 'plusnet plc',
    'comcast', 'comcast cable', 'xfinity',
    'charter', 'charter communications', 'spectrum',
    'cox', 'cox communications',
    'at&t', 'verizon',
    'bell canada', 'bell mobility',
    'rogers', 'rogers communications',
    'telus', 'telus communications',
    'shaw', 'shaw communications',
    'telstra', 'telstra corporation',
    'optus', 'optus australia',
    'jio', 'reliance jio',
    'airtel', 'bharti airtel',
    'china telecom', 'china unicom', 'china mobile',
    'sk telecom', 'sk broadband',
    'kt corporation', 'lg uplus',
    'turk telekom', 'turk telekomunikasyon',
    'turkcell',
    'bezeq', 'bezeq international',
    'partner', 'partner communications',
    'etisalat', 'etisalat uae',
    'stc', 'saudi telecom',
    'vodacom', 'mtn', 'telkom sa',
    'vivo', 'vivo brazil',
    'claro', 'claro brasil',
    'telcel', 'telcel mexico',
    'movistar mexico',
    'rostelecom', 'mts', 'beeline', 'megafon',
    'beltelecom', 'byfly',
    'kazakhtelecom',
    'telenet', 'telenet nv',
    'voo', 'edpnet',
    'sunrise', 'sunrise switzerland',
    'salt', 'salt switzerland',
    'fastweb', 'fastweb spa',
    'iliad', 'iliad italia',
    'masmovil', 'euskaltel', 'jazztel',
    'yoigo', 'pepephone',
    'meo', 'meo portugal',
    'nos', 'nos comunicacoes',
    'nowo',
    'p4 sp',
    'plus poland', 'polkomtel',
    'vectra', 'netia',
    'turknet', 'turknet iletisim',
    'superonline', 'millenicom',
    'tele2 sweden', 'tele2 ab',
    'com hem', 'bahnhof', 'bredband2',
    'bsnl', 'bsnl india',
    'mtnl',
    'vodafone idea', 'vi india',
    'act fibernet', 'hathway', 'excitel',
    'zen internet', 'gigaclear', 'hyperoptic',
    'tiscali', 'tiscali italia',
    'eolo', 'linkem',
    'altibox', 'lyse',
    'ice norway', 'get norway',
    'eastlink', 'teksavvy', 'sasktel',
    'aussie broadband', 'iinet', 'dodo',
    'internode', 'exetel', 'superloop',
    'cell c', 'rain',
    'safaricom', 'airtel kenya', 'telkom kenya',
    'maroc telecom', 'inwi',
    'mobily', 'zain', 'ooredoo',
    'azercell', 'bakcell', 'azertelecom', 'nar',
    'magticom', 'geocell', 'beeline georgia',
    'beeline armenia', 'vivacell', 'ucom',
    'orange moldova', 'moldcell', 'unite',
    'bite', 'tet', 'lmt', 'baltcom',
    // --- Added: more residential/mobile carriers, widening TP coverage as
    // detection net above widens, keeping FP rate down ---
    'ntt docomo', 'softbank', 'au kddi', 'kddi corporation',
    'viettel', 'vnpt', 'fpt telecom',
    'telkomsel', 'indosat', 'xl axiata',
    'pldt', 'globe telecom', 'smart communications',
    'ais thailand', 'true corporation', 'dtac',
    'maxis', 'celcom', 'digi telecommunications',
    'o2 czech republic', 't-mobile czech republic',
    'a1 telekom austria',
    'telekom romania', 'orange romania', 'vodafone romania',
    'a1 slovenia', 'telekom slovenije',
    'a1 bulgaria', 'vivacom', 'yettel bulgaria',
    'magyar telekom', 'telenor hungary', 'vodafone hungary',
    'orange slovakia', 'telekom slovakia',
    'play poland', 'plus poland',
    'globalstar', 'iridium communications',
    'du uae', 'etisalat by e&',
    'zong pakistan', 'jazz pakistan', 'telenor pakistan',
    'grameenphone', 'robi axiata', 'banglalink',
    'dialog axiata', 'mobitel sri lanka', 'hutch sri lanka',
    'ncell nepal', 'ntc nepal',
    'digicel', 'flow communications',
    'entel chile', 'entel peru', 'wom chile',
    'personal argentina', 'movistar argentina',
    'tigo', 'millicom',
];
// Live ASN lookup list for IpChecker's real-time (per-connection) ASN check.
// ASN membership is a verifiable technical fact (which network announces an
// IP's prefix over BGP), not a name-matching guess, so it's safe to use as
// its own corroborating source. To avoid ever introducing an unverified
// number that could point at the wrong (possibly residential) network, this
// list intentionally reuses ONLY the ASNs already individually confirmed via
// bgp.tools/IPinfo for ListUpdater's bulk per-ASN prefix download (see
// ListUpdater.ts sources list) - it does not add any new ASN numbers.
// Extend this list only after verifying a new ASN the same way, and add it
// to ListUpdater's sources too so the bulk static list stays in sync.
export const VERIFIED_HOSTING_VPN_ASNS: number[] = [
    14061, // DigitalOcean
    63949, // Linode
    20473, // Vultr / Choopa
    16276, // OVH
    24940, // Hetzner
    9009,  // M247
    60068, // Datacamp Limited / CDN77
    62240, // Clouvider
    49981, // WorldStream
    13335, // Cloudflare
    15169, // Google (GCP)
    8075,  // Microsoft (Azure)
    36351, // SoftLayer / IBM Cloud
    16509, // Amazon AWS
    // --- Added below: same verification standard as above (individually
    // confirmed via bgp.tools/IPinfo to be pure hosting/cloud/VPS
    // infrastructure with no residential subscriber base) ---
    12876,  // Scaleway / Online SAS (matches existing 'scaleway'/'online.net' keywords)
    51167,  // Contabo GmbH
    16265,  // LeaseWeb Netherlands B.V.
    45102,  // Alibaba (US) Technology Co., Ltd. / Alibaba Cloud
    132203, // Tencent Cloud Computing (Beijing) Co., Ltd
    202053, // UpCloud Ltd
    36352,  // ColoCrossing
    23470,  // ReliableSite.Net LLC
    53667,  // FranTech Solutions / BuyVM
    46844,  // Sharktech
    40676,  // Psychz Networks
    21859,  // Zenlayer Inc
    49505,  // Selectel Ltd
    53587,  // GTHost
    49453,  // Servers.com
    395954, // DataPacket LLC

    // --- v8 expansion: bulk-imported from brianhama/bad-asn-list (a
    // long-running, widely-used community ASN blocklist of cloud/hosting/
    // colo/VPS providers: https://github.com/brianhama/bad-asn-list).
    // Unlike a hand-picked few dozen, this pulls in the long tail of
    // regional/boutique VPS and dedicated-server hosts that individually
    // account for only a little traffic each but collectively cover a lot
    // of the "small VPN reseller running on some no-name host" case.
    //
    // Filtering methodology (kept deliberately stricter than the source
    // list, per this file's own false-positive-audit standard above):
    //   1. Included only if the registered org name contains a full
    //      hosting/datacenter/VPS/colo phrase (not the bare substring
    //      "host", which false-matches names like "EchoStar" or
    //      "Ghostnet") OR matches a known-good cloud/hosting brand name.
    //   2. Excluded outright regardless of name match: banks, universities,
    //      government/ministry entries, broadcasters, insurers, generic
    //      national telecom/broadband brands (e.g. CenturyLink, LTD
    //      Broadband) - these carry real residential/enterprise traffic
    //      that happened to appear in the same source list.
    //   3. A contiguous block of unrelated Nigerian ISP/utility ASNs
    //      (AS36873-AS37714) present in the upstream list was dropped
    //      entirely - it doesn't correspond to a single hosting entity and
    //      reads as accidental inclusion in the upstream source.
    // Re-verify periodically: hosting ASNs occasionally get resold/
    // repurposed, so this list should be refreshed the same way it was
    // built, not treated as permanently correct.
    3722, 3842, 6188, 7203, 7979, 8100, 8556, 9823, 9925, 10200, 10532,
    10929, 11230, 11235, 12617, 13209, 13647, 13739, 13909, 14120, 14160,
    14244, 14567, 14576, 14618, 14708, 14986, 14987, 14992, 15395, 15497, 15919,
    16397, 16862, 17439, 17669, 17881, 17918, 17920, 17971, 18120, 19133,
    19234, 19871, 19969, 20248, 20450, 20692, 22152, 22611, 22720, 23108,
    23273, 23881, 24381, 24549, 24558, 24611, 24725, 24931, 24958, 25048,
    26277, 26481, 26978, 27223, 27229, 27357, 27597, 27640, 28333, 28753,
    28855, 28997, 29067, 29140, 29302, 29311, 29331, 29452, 29713, 29748,
    29802, 29883, 30152, 30176, 30235, 30633, 31240, 31659, 31698, 31981,
    32097, 32181, 32244, 32275, 32475, 32647, 32740, 32780, 32911, 33070,
    33182, 33322, 33552, 34541, 35295, 35467, 35974, 36791, 37153, 38001,
    38279, 38894, 39451, 39704, 39839, 40244, 40281, 40374, 40539, 40715,
    40819, 41369, 41427, 41665, 42120, 42244, 42399, 42442, 42622, 42695,
    42699, 42705, 42831, 43021, 43198, 43620, 44066, 44398, 44901, 45152,
    45187, 45201, 45481, 45693, 46475, 46664, 47385, 47549, 47625, 48093,
    48812, 49485, 49834, 49949, 50608, 50926, 50968, 50986, 51241, 51294,
    52321, 52335, 52465, 52674, 53055, 53101, 53221, 53225, 53281, 53342,
    53850, 53914, 54334, 54527, 54540, 54641, 54817, 54825, 55229, 55293,
    55720, 55761, 56106, 56617, 56799, 57286, 57669, 57879, 58113, 58667,
    58797, 58922, 59135, 59253, 59554, 59615, 59705, 59795, 59854, 60476,
    60739, 60781, 60800, 61280, 62049, 62310, 62567, 62838, 62899, 63213,
    63916, 132425, 132509, 132717, 132869, 133752, 135822, 196745, 196827,
    197372, 197395, 197439, 197914, 198047, 198153, 198347, 198968, 199213,
    199481, 199847, 199997, 200000, 200147, 201597, 201634, 201709, 201983,
    202118, 206898, 262603, 262978, 262990, 394380,
];

// Brand names of purpose-built residential/mobile-proxy resale networks -
// services whose entire business is routing traffic through real
// consumer/mobile IPs on behalf of paying customers. Used only by
// ResidentialProxyDetector (see that file) as ONE of several independent
// signals it requires before raising its confidence score - never a
// standalone verdict, same posture as every other keyword list here.
export const RESIDENTIAL_PROXY_PROVIDERS: string[] = [
    'brightdata', 'bright data', 'luminati', 'luminati networks',
    'oxylabs', 'smartproxy', 'geosurf', 'netnut', 'netnut ltd',
    'iproyal', 'ip royal', 'soax', 'proxy-seller', 'proxyseller',
    'infatica', 'packetstream', 'proxyrack', 'stormproxies', 'storm proxies',
    'shifter.io', 'shifter io', 'proxyempire', 'proxy empire',
    'rayobyte', 'blazingseollc', 'blazing seo', 'asocks',
    'proxidize', 'massive networks proxy', 'apify proxy',
    'nimbleway', 'nimble way', 'bitproxies', 'thordata',
];

// Generic organization-naming patterns commonly used by proxy resellers
// when registering ASN/WHOIS org strings for pools of residential IPs
// they've contracted (as opposed to the ISP's own brand name, which is
// already covered by TRUSTED_PROVIDERS / hosting keyword lists). Kept
// short and specific to avoid the exact false-positive trap this file's
// v5.0 audit already documented for generic single words.
export const RESIDENTIAL_PROXY_ORG_HINTS: string[] = [
    'residential proxy', 'residential proxies', 'residential network pool',
    'p2p proxy network', 'peer to peer proxy',
];

// Combined list kept for backward compatibility with anything importing it;
// no longer used by IpChecker directly.
export const INSTANT_BAN_KEYWORDS: string[] = [
    ...VPN_KEYWORDS,
    ...DATACENTER_KEYWORDS,
    ...PROXY_KEYWORDS,
    ...HOSTING_KEYWORDS,
    'tor exit node', 'tor bridge relay',
];

// O(1) membership check for the hot per-connection ASN-index path
// (IpChecker Layer 0.5), instead of Array.prototype.includes doing a
// linear scan through ~280 numbers on every single new connection.
export const VERIFIED_HOSTING_VPN_ASNS_SET: Set<number> = new Set(VERIFIED_HOSTING_VPN_ASNS);

// Pre-normalized keyword/provider lists for IpChecker's keyword-matching
// layer. The keywords themselves never change at runtime, so normalizing
// each one (lowercase + strip punctuation) is done once here at module
// load instead of being redone on every single matchesKeywords()/
// isTrustedProvider() call for every player connection - same substring
// matching behavior, just without the repeated, wasted string work.
// Exported (v8.1) so DatasetLoader.ts can normalize user-supplied ISP/org
// dataset entries with the exact same rule used for every keyword list
// here, instead of drifting with a second copy of this logic.
export function normalizeProviderTextForIndex(text: string): string {
    return (text || '').toLowerCase().replace(/[^a-z0-9]+/gi, ' ').replace(/\s+/g, ' ').trim();
}
export const VPN_KEYWORDS_NORMALIZED: string[] = VPN_KEYWORDS.map(normalizeProviderTextForIndex);
export const PROXY_KEYWORDS_NORMALIZED: string[] = PROXY_KEYWORDS.map(normalizeProviderTextForIndex);
export const HOSTING_KEYWORDS_NORMALIZED: string[] = HOSTING_KEYWORDS.map(normalizeProviderTextForIndex);
export const DATACENTER_KEYWORDS_NORMALIZED: string[] = DATACENTER_KEYWORDS.map(normalizeProviderTextForIndex);
export const RESIDENTIAL_PROXY_PROVIDERS_NORMALIZED: string[] = RESIDENTIAL_PROXY_PROVIDERS.map(normalizeProviderTextForIndex);
export const RESIDENTIAL_PROXY_ORG_HINTS_NORMALIZED: string[] = RESIDENTIAL_PROXY_ORG_HINTS.map(normalizeProviderTextForIndex);
export const TRUSTED_PROVIDERS_NORMALIZED: string[] = TRUSTED_PROVIDERS.map(normalizeProviderTextForIndex);