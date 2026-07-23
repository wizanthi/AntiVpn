// src/services/MlDetector.ts
//
// WHAT THIS ACTUALLY IS
// ----------------------
// An online logistic-regression model that re-weights the signals
// IpChecker.ts already collects, trained continuously on this server's OWN
// confirmed history: every IP the existing ASN/API/keyword layers already
// banned becomes a positive example, every IP that cleared every single
// check becomes a negative example. That's real, available ground truth -
// there's no fabricated "learn from the internet" step, because that isn't
// a thing code can do. This model can never see a category of abuse your
// existing checks have never caught, because it has no labels for one; what
// it CAN do is notice combinations of your existing passive signals that
// individually sit just under each fixed threshold but together are a
// reliable tell - patterns a hand-tuned score/threshold system misses by
// construction.
//
// FEATURE SET - PASSIVE ONLY
// ----------------------------
// Every feature here comes from data IpChecker.ts already has in hand from
// its normal API battery - nothing here opens an extra connection to the
// player, probes their ports, or fingerprints their TLS stack. The prior
// version of this file had `ttl`, `openPorts`, `hasProxyHeaders`,
// `tlsVersion`, `cipherStrength`, `certValidityDays` - all of which require
// actively connecting to the PLAYER'S ip on some port to measure, which is
// exactly the category IpChecker.ts's own v5.0 changelog documents as
// removed for causing a real false-positive ban (an ordinary Ukrainian ISP
// customer). Those fields are gone here, not disabled - re-adding them
// would silently reopen that same failure mode.
//
// SAFETY POSTURE
// ----------------
// - Below MIN_TRAINING_SAMPLES this always returns a neutral, zero-effect
//   prediction (see getDefaultPrediction) - it cannot influence a verdict
//   before it has enough of the server's own history to learn from.
// - IpChecker only ever treats a prediction as corroboration for an
//   otherwise-borderline case (see the `Layer 3.5` comment where this is
//   wired in) - it is never wired as a sole, standalone ban reason, exactly
//   like every other single source in this file's multi-source-required
//   design.
import * as fs from 'fs';
import * as path from 'path';
import { Logger } from '../utils/Logger';
import { StorageAdapter } from './StorageAdapter';

export interface FeatureVector {
  ispLength: number;
  orgLength: number;
  ispHasVpnKeyword: boolean;
  ispHasHostingKeyword: boolean;
  ispHasProxyKeyword: boolean;
  asnNumber: number;
  verifiedAsnHit: boolean;      // hit against VERIFIED_HOSTING_VPN_ASNS (AsnIndex)
  apiVpnScore: number;
  apiVpnSources: number;
  apiProxyScore: number;
  apiProxySources: number;
  apiHostingScore: number;
  apiHostingSources: number;
  apiDatacenterScore: number;
  apiDatacenterSources: number;
  apiTorScore: number;
}

interface TrainingSample {
  features: FeatureVector;
  label: number; // 1 = confirmed VPN/proxy/hosting, 0 = confirmed clean
  weight: number;
}

interface ModelWeights { [key: string]: number; }

export interface PredictionResult {
  score: number;        // 0-100
  confidence: number;   // 0-1, distance from a coin-flip
  threatLevel: 'low' | 'medium' | 'high' | 'critical';
}

const FEATURE_KEYS: (keyof FeatureVector)[] = [
  'ispLength', 'orgLength', 'ispHasVpnKeyword', 'ispHasHostingKeyword', 'ispHasProxyKeyword',
  'asnNumber', 'verifiedAsnHit', 'apiVpnScore', 'apiVpnSources', 'apiProxyScore', 'apiProxySources',
  'apiHostingScore', 'apiHostingSources', 'apiDatacenterScore', 'apiDatacenterSources', 'apiTorScore',
];

export class MlDetector {
  private static instance: MlDetector;
  private logger: Logger;
  private weights: ModelWeights = {};
  private trainingData: TrainingSample[] = [];
  private modelPath: string;
  private dataPath: string;
  // When set (via initStorage), the model weights and training data persist
  // through the configured storage backend (file/sqlite/mysql - see
  // StorageAdapter.ts) instead of the raw data/*.json files below, so an
  // operator who chose MySQL keeps this "other" state in the same database
  // as everything else. Null until initStorage runs (and if it never does),
  // in which case the direct-to-disk fallback is used, preserving the
  // original behavior.
  private storageAdapter: StorageAdapter | null = null;
  private isInitialized = false;
  // Coalesces retrains scheduled off the hot path (see scheduleTrain).
  private trainScheduled = false;
  private readonly LEARNING_RATE = 0.05;
  private readonly EPOCHS = 60;
  private readonly MIN_TRAINING_SAMPLES = 50; // per-class balance isn't checked here on purpose - see predict()
  private featureStats: { [key: string]: { mean: number; std: number } } = {};

  private constructor() {
    this.logger = Logger.getInstance();
    this.modelPath = path.join(process.cwd(), 'data', 'ml_model.json');
    this.dataPath = path.join(process.cwd(), 'data', 'ml_training_data.json');
    for (const k of FEATURE_KEYS) this.weights[`${k}_weight`] = 0;
    this.weights.bias = 0;
    this.loadModel();
    this.loadTrainingData();
    if (this.trainingData.length >= this.MIN_TRAINING_SAMPLES) {
      try { this.train(); } catch (e) { this.logger.error('Initial ML training failed', e); }
    }
    this.isInitialized = true;
    this.logger.info(`MlDetector initialized with ${this.trainingData.length} samples (min ${this.MIN_TRAINING_SAMPLES} required before predictions count for anything)`);
  }

  static getInstance(): MlDetector {
    return MlDetector.instance || (MlDetector.instance = new MlDetector());
  }

  // Switch persistence over to the configured storage backend. Called once
  // at startup (index.ts). Loads whatever the backend already holds - which
  // supersedes the direct-from-disk load the constructor did as a fallback -
  // and, from this point on, every saveModel()/saveTrainingData() writes
  // through the adapter (so on MySQL the model + training data live in the
  // same database as the lists/IPs/datasets, not in loose data/*.json files).
  async initStorage(adapter: StorageAdapter): Promise<void> {
    this.storageAdapter = adapter;
    try {
      const model = await adapter.read('ml_model');
      if (model) {
        if (model.weights) this.weights = { ...this.weights, ...model.weights };
        if (model.featureStats) this.featureStats = model.featureStats;
      }
      const data = await adapter.read('ml_training_data');
      if (Array.isArray(data)) this.trainingData = data;

      // Re-fit on whatever the backend supplied so the in-memory weights
      // match the loaded training set (a no-op below the sample floor).
      if (this.trainingData.length >= this.MIN_TRAINING_SAMPLES) {
        try { this.train(); } catch (e) { this.logger.error('ML training after storage load failed', e); }
      }
      this.logger.info(`MlDetector storage initialized via ${adapter.kind} backend (${this.trainingData.length} samples)`);
    } catch (e) {
      this.logger.warn('MlDetector: failed to load from storage backend, keeping current state', e);
    }
  }

  private loadModel(): void {
    try {
      if (fs.existsSync(this.modelPath)) {
        const data = JSON.parse(fs.readFileSync(this.modelPath, 'utf-8'));
        if (data.weights) this.weights = { ...this.weights, ...data.weights };
        if (data.featureStats) this.featureStats = data.featureStats;
      }
    } catch { this.logger.warn('Failed to load ML model, using defaults'); }
  }

  private saveModel(): void {
    const payload = {
      weights: this.weights, featureStats: this.featureStats,
      trainedAt: new Date().toISOString(), samples: this.trainingData.length,
    };
    // Route through the storage backend when one is configured (MySQL/SQLite/
    // file), so this state lands wherever the operator chose. Fire-and-forget
    // either way - these run alongside player-check processing.
    if (this.storageAdapter) {
      this.storageAdapter.write('ml_model', payload).catch(() => this.logger.error('Failed to save ML model'));
      return;
    }
    try {
      const dir = path.dirname(this.modelPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      // Async + compact: these run alongside player-check processing, so a
      // synchronous writeFileSync here would stall the event loop (and every
      // other in-flight connection check) for the duration of the write.
      fs.promises.writeFile(this.modelPath, JSON.stringify(payload))
        .catch(() => this.logger.error('Failed to save ML model'));
    } catch { this.logger.error('Failed to save ML model'); }
  }

  private loadTrainingData(): void {
    try {
      if (fs.existsSync(this.dataPath)) this.trainingData = JSON.parse(fs.readFileSync(this.dataPath, 'utf-8'));
    } catch { this.logger.warn('Failed to load ML training data'); }
  }

  private saveTrainingData(): void {
    const trimmed = this.trainingData.slice(-20000);
    if (this.storageAdapter) {
      this.storageAdapter.write('ml_training_data', trimmed).catch(() => this.logger.error('Failed to save ML training data'));
      return;
    }
    try {
      const dir = path.dirname(this.dataPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      // Async + compact (was writeFileSync + pretty-print of up to 20k
      // samples): the pretty-print roughly doubled the bytes and the sync
      // write blocked the event loop on the connection path.
      fs.promises.writeFile(this.dataPath, JSON.stringify(trimmed))
        .catch(() => this.logger.error('Failed to save ML training data'));
    } catch { this.logger.error('Failed to save ML training data'); }
  }

  // Builds a feature vector straight out of data IpChecker.ts's
  // gatherApiVerdict() / AsnIndex lookup already produced for this
  // connection - no extra I/O.
  extractFeatures(data: {
    isp?: string; org?: string; asn?: number; verifiedAsnHit?: boolean;
    vpnScore?: number; vpnSources?: number; proxyScore?: number; proxySources?: number;
    hostingScore?: number; hostingSources?: number; datacenterScore?: number; datacenterSources?: number;
    torScore?: number;
  }): FeatureVector {
    return {
      ispLength: data.isp?.length || 0,
      orgLength: data.org?.length || 0,
      ispHasVpnKeyword: this.containsVpnKeyword(data.isp || ''),
      ispHasHostingKeyword: this.containsHostingKeyword(data.isp || ''),
      ispHasProxyKeyword: this.containsProxyKeyword(data.isp || ''),
      asnNumber: data.asn || 0,
      verifiedAsnHit: !!data.verifiedAsnHit,
      apiVpnScore: data.vpnScore || 0,
      apiVpnSources: data.vpnSources || 0,
      apiProxyScore: data.proxyScore || 0,
      apiProxySources: data.proxySources || 0,
      apiHostingScore: data.hostingScore || 0,
      apiHostingSources: data.hostingSources || 0,
      apiDatacenterScore: data.datacenterScore || 0,
      apiDatacenterSources: data.datacenterSources || 0,
      apiTorScore: data.torScore || 0,
    };
  }

  predict(features: FeatureVector): PredictionResult {
    // Not enough of the server's own history yet - stay neutral rather
    // than let a near-random model weigh in on real players.
    if (!this.isInitialized || this.trainingData.length < this.MIN_TRAINING_SAMPLES) {
      return { score: 0, confidence: 0, threatLevel: 'low' };
    }
    try {
      const nf = this.normalizeFeatures(features);
      let score = this.weights.bias || 0;
      for (const k of FEATURE_KEYS) {
        const v = nf[k];
        score += (typeof v === 'boolean' ? (v ? 1 : 0) : v) * (this.weights[`${k}_weight`] || 0);
      }
      const probability = this.sigmoid(score);
      const confidence = Math.min(0.95, Math.abs(probability - 0.5) * 2);
      let threatLevel: PredictionResult['threatLevel'] = 'low';
      if (probability > 0.9) threatLevel = 'critical';
      else if (probability > 0.7) threatLevel = 'high';
      else if (probability > 0.4) threatLevel = 'medium';
      return { score: Math.round(probability * 100), confidence: Math.round(confidence * 100) / 100, threatLevel };
    } catch (e) {
      this.logger.error('ML prediction failed', e);
      return { score: 0, confidence: 0, threatLevel: 'low' };
    }
  }

  // Called by IpChecker once a verdict is final for a connection - label=1
  // for a confirmed ban (any layer), label=0 only for an IP that cleared
  // every single check (true "clean", not just "didn't hit the ban bar").
  addTrainingSample(features: FeatureVector, label: 0 | 1, weight: number = 1): void {
    this.trainingData.push({ features, label, weight });
    if (this.trainingData.length > 20000) this.trainingData = this.trainingData.slice(-20000);
    if (this.trainingData.length % 25 === 0) this.scheduleTrain();
  }

  // Retraining is CPU-heavy (EPOCHS passes over up to 20k samples). This is
  // invoked from IpChecker's per-connection verdict path, so run it on a
  // later event-loop tick instead of synchronously inside the player's
  // awaited check - and coalesce, so a burst that crosses several 25-sample
  // boundaries triggers at most one retrain rather than stacking them.
  private scheduleTrain(): void {
    if (this.trainScheduled) return;
    this.trainScheduled = true;
    setImmediate(() => {
      this.trainScheduled = false;
      try { this.train(); this.saveTrainingData(); } catch (e) { this.logger.error('ML retrain failed', e); }
    });
  }

  private train(): void {
    if (this.trainingData.length < 10) return;
    this.updateFeatureStats();
    const normalized = this.trainingData.map(s => ({
      features: this.normalizeFeatures(s.features), label: s.label, weight: s.weight,
    }));

    for (let epoch = 0; epoch < this.EPOCHS; epoch++) {
      // Fisher-Yates: a real uniform shuffle. `sort(() => Math.random()-0.5)`
      // is not - its comparator is inconsistent, so it biases SGD sample
      // ordering (and cost an O(n log n) sort per epoch on top).
      const shuffled = normalized.slice();
      for (let i = shuffled.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        const tmp = shuffled[i]; shuffled[i] = shuffled[j]; shuffled[j] = tmp;
      }
      let totalLoss = 0;
      for (const sample of shuffled) {
        const prediction = this.predictRaw(sample.features);
        const error = sample.label - prediction;
        const gradient = error * prediction * (1 - prediction);
        const l2 = 0.001;
        this.weights.bias += this.LEARNING_RATE * gradient * sample.weight;
        for (const k of FEATURE_KEYS) {
          const v = sample.features[k];
          const fv = typeof v === 'boolean' ? (v ? 1 : 0) : v;
          const wk = `${k}_weight`;
          this.weights[wk] += this.LEARNING_RATE * (gradient * fv * sample.weight - l2 * this.weights[wk]);
        }
        totalLoss += error * error;
      }
      if (totalLoss / shuffled.length < 0.001) break;
    }
    this.saveModel();
    this.logger.info(`MlDetector retrained on ${this.trainingData.length} samples`);
  }

  private predictRaw(nf: FeatureVector): number {
    let score = this.weights.bias || 0;
    for (const k of FEATURE_KEYS) {
      const v = nf[k];
      score += (typeof v === 'boolean' ? (v ? 1 : 0) : v) * (this.weights[`${k}_weight`] || 0);
    }
    return this.sigmoid(score);
  }

  private normalizeFeatures(features: FeatureVector): FeatureVector {
    const out: any = {};
    for (const k of FEATURE_KEYS) {
      const v = features[k];
      if (typeof v === 'boolean') { out[k] = v; continue; }
      const stats = this.featureStats[k];
      out[k] = stats && stats.std > 0 ? (v - stats.mean) / stats.std : v;
    }
    return out as FeatureVector;
  }

  private updateFeatureStats(): void {
    for (const k of FEATURE_KEYS) {
      const values = this.trainingData.map(s => s.features[k]).filter((v): v is number => typeof v === 'number');
      if (!values.length) continue;
      const mean = values.reduce((a, b) => a + b, 0) / values.length;
      const variance = values.reduce((a, b) => a + (b - mean) ** 2, 0) / values.length;
      this.featureStats[k] = { mean, std: Math.sqrt(variance) || 1 };
    }
  }

  private sigmoid(x: number): number { return 1 / (1 + Math.exp(-x)); }

  private containsVpnKeyword(str: string): boolean {
    const keywords = ['vpn', 'nord', 'express', 'surfshark', 'cyberghost', 'proton', 'mullvad', 'windscribe', 'hidemyass', 'tunnelbear', 'hotspot', 'ipvanish', 'purevpn', 'privatevpn', 'trustzone', 'airvpn', 'ivpn', 'ovpn', 'strongvpn', 'torguard'];
    const lower = str.toLowerCase();
    return keywords.some(k => lower.includes(k));
  }
  private containsHostingKeyword(str: string): boolean {
    const keywords = ['hosting', 'server', 'cloud', 'vps', 'vds', 'dedicated', 'datacenter', 'colo', 'digitalocean', 'linode', 'vultr', 'ovh', 'hetzner', 'aws', 'azure', 'gcp'];
    const lower = str.toLowerCase();
    return keywords.some(k => lower.includes(k));
  }
  private containsProxyKeyword(str: string): boolean {
    const keywords = ['proxy', 'proxies', 'socks', 'shadowsocks', 'v2ray', 'trojan', 'xray', 'vmess', 'vless', 'hysteria', 'brightdata', 'luminati', 'oxylabs', 'smartproxy', 'geosurf', 'netnut'];
    const lower = str.toLowerCase();
    return keywords.some(k => lower.includes(k));
  }

  getStats(): { samples: number; positiveSamples: number; negativeSamples: number; readyToPredict: boolean; lastTrained: string } {
    const positive = this.trainingData.filter(s => s.label === 1).length;
    return {
      samples: this.trainingData.length,
      positiveSamples: positive,
      negativeSamples: this.trainingData.length - positive,
      readyToPredict: this.trainingData.length >= this.MIN_TRAINING_SAMPLES,
      lastTrained: new Date().toISOString(),
    };
  }

  reset(): void {
    this.weights = {}; this.featureStats = {}; this.trainingData = [];
    for (const k of FEATURE_KEYS) this.weights[`${k}_weight`] = 0;
    this.weights.bias = 0;
    this.saveModel(); this.saveTrainingData();
    this.logger.info('ML model reset to initial state');
  }
}
