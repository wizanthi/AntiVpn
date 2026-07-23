import * as fs from 'fs';
import * as path from 'path';
import { AppConfig } from '../types';
import { DEFAULT_DETECTION_CONFIG, deepMergeDefaults } from './DetectionDefaults';
import { DEFAULT_DATASETS_CONFIG } from './DatasetsDefaults';
import { DEFAULT_APIS_CONFIG } from './ApisDefaults';
import { DEFAULT_STORAGE_CONFIG } from './StorageDefaults';

// Configuration manager - singleton pattern
export class ConfigManager {
  private static instance: ConfigManager;
  private config!: AppConfig;
  // The config.json document exactly as it exists on disk (no merged-in
  // defaults). setValue() edits and rewrites THIS object, so a chat-command
  // change never bakes the entire default tree into the operator's file.
  private rawConfig: any = {};

  private constructor() {}

  static getInstance(): ConfigManager {
    if (!ConfigManager.instance) {
      ConfigManager.instance = new ConfigManager();
    }
    return ConfigManager.instance;
  }

  // Load and validate configuration from file
  load(): AppConfig {
    const configPath = path.join(process.cwd(), 'config.json');
    
    if (!fs.existsSync(configPath)) {
      throw new Error(`Config file not found: ${configPath}`);
    }

    const raw = fs.readFileSync(configPath, 'utf-8');
    this.rawConfig = JSON.parse(raw);
    this.config = JSON.parse(raw) as AppConfig;

    // Deep-merge the reputation/scoring-engine defaults so an existing
    // config.json with no `detection` block (or only a partial one) keeps
    // working unchanged - every weight/threshold/toggle simply falls back
    // to DEFAULT_DETECTION_CONFIG. This never overwrites anything the
    // operator actually specified.
    this.config.detection = deepMergeDefaults(DEFAULT_DETECTION_CONFIG, this.config.detection);
    this.config.datasets = deepMergeDefaults(DEFAULT_DATASETS_CONFIG, this.config.datasets);
    this.config.apis = deepMergeDefaults(DEFAULT_APIS_CONFIG, this.config.apis);
    this.config.storage = deepMergeDefaults(DEFAULT_STORAGE_CONFIG, this.config.storage);

    // Validate required fields
    this.validate();
    
    return this.config;
  }

  // Validate required configuration fields
  private validate(): void {
    const required = [
      'server.host',
      'server.port',
      'server.rcon_password',
      'discord.webhook_url',
      'monitoring.status_interval_seconds'
    ];

    for (const key of required) {
      const value = key.split('.').reduce((obj, k) => obj?.[k], this.config as any);
      if (!value && value !== 0) {
        throw new Error(`Missing required config: ${key}`);
      }
    }

    console.log('Config validated successfully');
  }

  // Get specific config value
  get<K extends keyof AppConfig>(key: K): AppConfig[K] {
    return this.config[key];
  }

  // Get all config values
  getAll(): AppConfig {
    return { ...this.config };
  }

  // Read a value by dotted path (e.g. "auto_ban.ban_reason") from the fully
  // merged live config. Returns undefined for unknown paths.
  getValue(path: string): any {
    return path.split('.').reduce((obj: any, k: string) => (obj == null ? undefined : obj[k]), this.config as any);
  }

  // Master switch (config.json -> antivpn.enabled), toggled at runtime by
  // the in-game `$sudo antivpn enable 1/0` command. Read live on every hot
  // path (join checks, status scans, custom-ban sync) rather than cached at
  // startup, so a toggle takes effect immediately - and because setValue()
  // persists it, the choice survives the hourly reconnect AND full
  // restarts. Absent means enabled.
  isAntiVpnEnabled(): boolean {
    return this.getValue('antivpn.enabled') !== false;
  }

  // Set a value by dotted path on BOTH the live merged config (so running
  // services that re-read ConfigManager pick it up) and the raw on-disk
  // document, then persist config.json. Used by the in-game admin commands
  // (AdminCommandService) - callers are responsible for restricting which
  // paths may be edited. Throws if the write fails.
  setValue(dottedPath: string, value: any): void {
    const keys = dottedPath.split('.');
    const setOn = (root: any) => {
      let obj = root;
      for (const key of keys.slice(0, -1)) {
        if (obj[key] === undefined || obj[key] === null || typeof obj[key] !== 'object') obj[key] = {};
        obj = obj[key];
      }
      obj[keys[keys.length - 1]] = value;
    };
    setOn(this.config as any);
    setOn(this.rawConfig);

    const configPath = path.join(process.cwd(), 'config.json');
    // Write-then-rename so a crash mid-write can't truncate config.json.
    const tmpPath = `${configPath}.tmp`;
    fs.writeFileSync(tmpPath, JSON.stringify(this.rawConfig, null, 2) + '\n', 'utf-8');
    fs.renameSync(tmpPath, configPath);
  }
}