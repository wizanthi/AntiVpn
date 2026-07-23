// src/config/ApisDefaults.ts
//
// Default values for the `apis` config.json block - per-service enable
// toggle and API key/credential for the Layer 1 IP-intelligence API battery
// in IpChecker.ts. Deep-merged into whatever `apis` block (if any) exists in
// config.json by ConfigManager (see DetectionDefaults.ts's deepMergeDefaults,
// reused here), same pattern as DEFAULT_DETECTION_CONFIG /
// DEFAULT_DATASETS_CONFIG:
//   - An existing config.json with no `apis` key at all keeps working
//     exactly as before (every service enabled, no config.json key -
//     env vars still apply as a fallback).
//   - An operator can override just the fields they care about (e.g. only
//     `apis.ipinfo_api.api_key`) without restating the whole block.
//
// api_key is omitted here for the 5 services that are public/keyless by
// design (ipapi, ipwhois, ipapico, ipapi.is, rdap) - they only get the
// enabled toggle. getipintel_api's api_key holds a contact email, not a key
// - that's the credential getipintel.net actually uses.
import { ApisConfig } from '../types';

export const DEFAULT_APIS_CONFIG: ApisConfig = {
  ipapi_api: { enabled: true },
  ipwhois_api: { enabled: true },
  ipapico_api: { enabled: true },
  ipinfo_api: { enabled: true, api_key: '' },
  vpnapi_api: { enabled: true, api_key: '' },
  proxycheck_api: { enabled: true, api_key: '' },
  ipquality_api: { enabled: true, api_key: '' },
  abuseipdb_api: { enabled: true, api_key: '' },
  ipapiis_api: { enabled: true },
  rdap_api: { enabled: true },
  getipintel_api: { enabled: true, api_key: '' },
  iplocate_api: { enabled: true, api_key: '' },
  ipregistry_api: { enabled: true, api_key: '' },
};
