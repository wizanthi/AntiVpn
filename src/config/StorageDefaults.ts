// src/config/StorageDefaults.ts
//
// Default values for the `storage` config.json block (see StorageAdapter.ts).
// Deep-merged into config.json's `storage` block by ConfigManager, same
// pattern as DatasetsDefaults.ts/ApisDefaults.ts - an operator only has to
// specify the fields they want to change.
//
// type: 'file' (default) keeps every store on the existing data/*.json
// files, byte-for-byte the same as before this option existed. Set to
// 'sqlite' or 'mysql' to move blacklist/whitelist/custombans/ip_reputation/
// network_reputation/checked_ips into that database instead.
import { StorageConfig } from '../types';

export const DEFAULT_STORAGE_CONFIG: StorageConfig = {
  type: 'file',
  sqlite: {
    path: 'data/antivpn.sqlite',
  },
  mysql: {
    host: 'localhost',
    port: 3306,
    user: '',
    password: '',
    database: 'antivpn',
    connection_limit: 5,
  },
};
