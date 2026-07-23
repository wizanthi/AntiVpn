import axios, { AxiosInstance } from 'axios';
import { AlertPayload, IpCheckResult, TrackedPlayer } from '../types';
import { Logger } from '../utils/Logger';
import { ConfigManager } from '../config/ConfigManager';
import { sharedKeepAliveHttpsAgent } from '../utils/HttpAgents';

// Webhook service for Discord notifications - singleton pattern
export class WebhookService {
  private static instance: WebhookService;
  private mainWebhook: AxiosInstance;
  private alertWebhook: AxiosInstance | null = null;
  private logger: Logger;
  private alertQueue: AlertPayload[] = [];
  private flushInterval: NodeJS.Timeout | null = null;
  private serverAddress: string;
  private mode: string;
  private autoBanEnabled: boolean;

  // Proactive spacing between posts to the SAME webhook. Discord rate-limits
  // webhooks at ~30 requests/minute; staying at ~28/min (2100ms apart) keeps
  // us under the cap so we rarely see a 429 at all. A single burst of
  // per-player posts (processStatus fans out one webhook per player, in
  // parallel batches) would otherwise blow straight past this.
  private static readonly MIN_INTERVAL_MS = 2100;

  // Per-webhook send state. Each webhook (main + alert) gets its own Discord
  // rate-limit bucket, so it gets its own serialization chain and backoff
  // clock. `chain` guarantees only one request per webhook is in flight at a
  // time; `nextAllowedAt` is the epoch-ms before which the next post must not
  // be sent (advanced by MIN_INTERVAL_MS normally, or by a 429 retry_after).
  private channels = new Map<AxiosInstance, { chain: Promise<void>; nextAllowedAt: number }>();

  private constructor(mainUrl: string, alertUrl?: string) {
    this.logger = Logger.getInstance();
    
    try {
      const config = ConfigManager.getInstance().getAll();
      this.serverAddress = `${config.server.host}:${config.server.port}`;
      this.mode = config.auto_ban?.mode || 'warn';
      this.autoBanEnabled = config.auto_ban?.enabled || false;
    } catch {
      this.serverAddress = 'Unknown';
      this.mode = 'warn';
      this.autoBanEnabled = false;
    }
    
    this.mainWebhook = axios.create({
      baseURL: mainUrl,
      timeout: 10000,
      httpsAgent: sharedKeepAliveHttpsAgent,
      headers: { 'Content-Type': 'application/json' }
    });

    if (alertUrl) {
      this.alertWebhook = axios.create({
        baseURL: alertUrl,
        timeout: 10000,
        httpsAgent: sharedKeepAliveHttpsAgent,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Flush alerts every 30 seconds
    this.flushInterval = setInterval(() => this.flushAlerts(), 30000);
  }

  static getInstance(mainUrl?: string, alertUrl?: string): WebhookService {
    if (!WebhookService.instance) {
      if (!mainUrl) throw new Error('Main webhook URL required');
      WebhookService.instance = new WebhookService(mainUrl, alertUrl);
    }
    return WebhookService.instance;
  }

  // Send info embed
  async sendInfo(title: string, description: string, fields?: Array<{name: string; value: string; inline?: boolean}>): Promise<void> {
    await this.sendEmbed(this.mainWebhook, {
      color: 0x3498db,
      title,
      description,
      fields,
      timestamp: new Date().toISOString(),
      footer: { text: `WizanthiAntiVpn • ${this.serverAddress}`, icon_url: 'https://i.ibb.co/yFwJ3nDh/image.jpg' }
    });
  }

  // Send warning embed
  async sendWarning(title: string, description: string, fields?: Array<{name: string; value: string; inline?: boolean}>): Promise<void> {
    await this.sendEmbed(this.mainWebhook, {
      color: 0xf1c40f,
      title: `${title}`,
      description,
      fields,
      timestamp: new Date().toISOString(),
      footer: { text: `WizanthiAntiVpn • ${this.serverAddress}`, icon_url: 'https://i.ibb.co/yFwJ3nDh/image.jpg' }
    });
  }

  // Send error embed
  async sendError(title: string, description: string, fields?: Array<{name: string; value: string; inline?: boolean}>): Promise<void> {
    await this.sendEmbed(this.mainWebhook, {
      color: 0xe74c3c,
      title: `${title}`,
      description,
      fields,
      timestamp: new Date().toISOString(),
      footer: { text: `WizanthiAntiVpn • ${this.serverAddress}`, icon_url: 'https://i.ibb.co/yFwJ3nDh/image.jpg' }
    });
  }

  // Queue alert for sending
  async sendAlert(alert: AlertPayload): Promise<void> {
    this.alertQueue.push(alert);
    if (alert.severity === 'critical') await this.flushAlerts();
  }

  // Send VPN detection alert
  async sendVpnDetectionAlert(player: TrackedPlayer, ipCheck: IpCheckResult): Promise<void> {
    const detectionType = this.getDetectionType(ipCheck);
    
    const colorMap: Record<string, number> = {
      'critical': 0x992d22, 'high': 0xe74c3c, 'medium': 0xf1c40f, 'low': 0x3498db
    };

    const threatEmoji: Record<string, string> = {
      'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'
    };

    const embed = {
      color: colorMap[ipCheck.threat_level || 'low'] || 0xe74c3c,
      author: {
        name: 'WizanthiAntiVpn v2.0.0',
        icon_url: 'https://i.ibb.co/yFwJ3nDh/image.jpg'
      },
      title: `${detectionType} DETECTED`,
      description: 
        '```yaml\n' +
        `${detectionType}\n` +
        `   ├─ Nick: ${player.nickname}\n` +
        `   ├─ ID: ${player.id}  |  Clan: ${player.clan || 'None'}\n` +
        `   ├─ IP: ${player.ip}\n` +
        `   ├─ Country: ${ipCheck.country || 'Unknown'}\n` +
        `   ├─ City: ${ipCheck.city || 'Unknown'}\n` +
        `   ├─ ISP: ${ipCheck.isp || 'Unknown'}\n` +
        `   ├─ Org: ${ipCheck.organization || 'Unknown'}\n` +
        `   ├─ Risk Score: ${ipCheck.risk_score || 0}/100\n` +
        `   ├─ Threat: ${(ipCheck.threat_level || 'low').toUpperCase()}\n` +
        `   └─ Whitelist: ${player.flags.is_whitelisted ? 'YES' : 'NO'} | Blacklist: ${player.flags.is_blacklisted ? 'YES' : 'NO'}\n` +
        '```',
      fields: [
        { name: 'Nickname', value: `\`${player.nickname}\``, inline: true },
        { name: 'ID', value: String(player.id), inline: true },
        { name: 'Clan', value: player.clan || 'None', inline: true },
        { name: 'IP', value: `\`${player.ip}\``, inline: true },
        { name: 'Country', value: ipCheck.country || 'Unknown', inline: true },
        { name: 'City', value: ipCheck.city || 'Unknown', inline: true },
        { name: 'ISP', value: ipCheck.isp || 'Unknown', inline: true },
        { name: 'Organization', value: ipCheck.organization || 'Unknown', inline: true },
        { name: 'Risk Score', value: `${ipCheck.risk_score || 0}/100`, inline: true },
        { name: `${threatEmoji[ipCheck.threat_level || 'low']} Threat`, value: (ipCheck.threat_level || 'low').toUpperCase(), inline: true },
        { name: 'Detection', value: detectionType, inline: true },
        {
          name: 'Details',
          value: [
            `VPN: ${ipCheck.is_vpn ? 'YES' : 'No'}`,
            `Proxy: ${ipCheck.is_proxy ? 'YES' : 'No'}`,
            `TOR: ${ipCheck.is_tor ? 'YES' : 'No'}`,
            `Hosting: ${ipCheck.is_hosting ? 'YES' : 'No'}`,
            `Datacenter: ${ipCheck.is_datacenter ? 'YES' : 'No'}`
          ].join(' | '),
          inline: false
        },
        // v8.0: surfaces exactly why the weighted score was assigned
        // (requirement #8) - only present when the risk-scoring engine ran
        // (i.e. not on the older, purely-boolean ban paths' minimal
        // fast-path results), so this degrades gracefully either way.
        ...(ipCheck.risk_breakdown && ipCheck.risk_breakdown.length > 0 ? [{
          name: '📊 Score Breakdown',
          value: '```diff\n' + ipCheck.risk_breakdown.map(b => `${b.weight >= 0 ? '+' : ''}${b.weight} ${b.label}`).join('\n') +
            `\n= ${ipCheck.risk_score || 0} (${(ipCheck.risk_level || 'unknown').replace('_', ' ')})` + '\n```',
          inline: false
        }] : []),
        { name: 'Whitelist', value: player.flags.is_whitelisted ? 'YES' : 'NO', inline: true },
        { name: 'Blacklist', value: player.flags.is_blacklisted ? 'YES' : 'NO', inline: true },
        { name: 'Time', value: new Date().toLocaleString('en-US', { timeZone: 'UTC' }), inline: true },
        { name: 'Server', value: `\`${this.serverAddress}\``, inline: true },
        { name: 'Mode', value: `${this.mode.toUpperCase()} | AutoBan: ${this.autoBanEnabled ? 'ON' : 'OFF'}`, inline: true }
      ],
      thumbnail: { url: 'https://ibb.co/gZ5CnMGv' },
      timestamp: new Date().toISOString(),
      footer: { text: `WizanthiAntiVpn • ${this.serverAddress} • ${this.mode.toUpperCase()}`, icon_url: 'https://i.ibb.co/yFwJ3nDh/image.jpg' }
    };

    const targetWebhook = this.alertWebhook || this.mainWebhook;
    await this.sendEmbed(targetWebhook, embed);
    this.logger.info(`Alert sent for ${player.nickname}`);
  }

  // Send clean player info
  async sendCleanPlayerInfo(player: TrackedPlayer, ipCheck: IpCheckResult): Promise<void> {
    const time = new Date().toLocaleString('en-US', { timeZone: 'UTC' });
    
    const embed = {
      color: 0x2ecc71,
      author: {
        name: 'WizanthiAntiVpn v2.0.0',
        icon_url: 'https://i.ibb.co/yFwJ3nDh/image.jpg'
      },
      title: `Clean: ${player.nickname}`,
      description:
        '```yaml\n' +
        `CLEAN | ${time}\n` +
        `   ├─ Nick: ${player.nickname}\n` +
        `   ├─ ID: ${player.id}  |  Clan: ${player.clan || 'None'}\n` +
        `   ├─ IP: ${player.ip}\n` +
        `   ├─ Country: ${ipCheck.country || 'Unknown'}\n` +
        `   ├─ City: ${ipCheck.city || 'Unknown'}\n` +
        `   ├─ ISP: ${ipCheck.isp || 'Unknown'}\n` +
        `   └─ Score: ${ipCheck.risk_score || 0}/100\n` +
        '```',
      fields: [
        { name: 'Nickname', value: player.nickname, inline: true },
        { name: 'ID', value: String(player.id), inline: true },
        { name: 'Clan', value: player.clan || 'None', inline: true },
        { name: 'IP', value: `\`${player.ip}\``, inline: true },
        { name: 'Country', value: ipCheck.country || 'Unknown', inline: true },
        { name: 'City', value: ipCheck.city || 'Unknown', inline: true },
        { name: 'ISP', value: ipCheck.isp || 'Unknown', inline: true },
        { name: 'Organization', value: ipCheck.organization || 'Unknown', inline: true },
        { name: 'Risk Score', value: `${ipCheck.risk_score || 0}/100`, inline: true },
        { name: 'Status', value: 'CLEAN', inline: true },
        { name: 'Server', value: `\`${this.serverAddress}\``, inline: true }
      ],
      timestamp: new Date().toISOString(),
      footer: { text: `WizanthiAntiVpn • ${this.serverAddress}`, icon_url: 'https://i.ibb.co/yFwJ3nDh/image.jpg' }
    };

    const targetWebhook = this.alertWebhook || this.mainWebhook;
    await this.sendEmbed(targetWebhook, embed);
  }

  // Send startup message
  async sendStartupMessage(config: { server: string; whitelist: number; blacklist: number }): Promise<void> {
    const modeColor = this.mode === 'autoban' ? '🔴' : '🟡';
    
    const embed = {
      color: 0x5865f2,
      author: {
        name: 'WizanthiAntiVpn v2.0.0',
        icon_url: 'https://i.ibb.co/yFwJ3nDh/image.jpg'
      },
      title: 'Bot Started',
      description:
      '```\n' +
     '╔══════════════════════════════════════╗\n' +
     '║                                                 ║\n' +
     '║  🛡️  WizanthiAntiVpn  v2.0.0                   ║\n' +
     '║  DDNet Anti-Abuse Security System               ║\n' +
     '║                                                 ║\n' +
     '╚══════════════════════════════════════╝\n' +
     '```\n' +
        `**Server:** \`${this.serverAddress}\`\n` +
        `${modeColor} **Mode:** ${this.mode.toUpperCase()}\n` +
        `**AutoBan:** ${this.autoBanEnabled ? 'ON' : 'OFF'}\n` +
        `**Whitelist:** ${config.whitelist} IPs\n` +
        `**Blacklist:** ${config.blacklist} IPs\n\n` +
        `**Monitoring started**`,
      thumbnail: { url: 'https://ibb.co/gZ5CnMGv' },
      timestamp: new Date().toISOString(),
      footer: { text: `WizanthiAntiVpn • ${this.serverAddress}`, icon_url: 'https://i.ibb.co/yFwJ3nDh/image.jpg' }
    };

    await this.sendEmbed(this.mainWebhook, embed);
  }

  // Send auto-ban notification
  async sendAutoBan(player: TrackedPlayer, ipCheck: IpCheckResult): Promise<void> {
    const embed = {
      color: 0xe74c3c,
      title: 'Auto-Ban',
      description:
        '```yaml\n' +
        `BANNED\n` +
        `   ├─ Nick: ${player.nickname}\n` +
        `   ├─ ID: ${player.id}\n` +
        `   ├─ IP: ${player.ip}\n` +
        `   └─ Score: ${ipCheck.risk_score || 0}/100\n` +
        '```',
      fields: [
        { name: 'Player', value: player.nickname, inline: true },
        { name: 'ID', value: String(player.id), inline: true },
        { name: 'IP', value: `\`${player.ip}\``, inline: true },
        { name: 'ISP', value: ipCheck.isp || 'Unknown', inline: true },
        { name: 'Score', value: `${ipCheck.risk_score || 0}/100`, inline: true },
        { name: 'Mode', value: 'AUTOBAN', inline: true },
        { name: 'Server', value: `\`${this.serverAddress}\``, inline: true }
      ],
      timestamp: new Date().toISOString(),
      footer: { text: `WizanthiAntiVpn • ${this.serverAddress} • AUTOBAN`, icon_url: 'https://i.ibb.co/yFwJ3nDh/image.jpg' }
    };

    await this.sendEmbed(this.mainWebhook, embed);
  }

  // Send quarantine/review alert. A SOFT (medium-confidence) detection that
  // was time-boxed instead of permanently banned, surfaced for a human to
  // confirm or lift. Routed to the alert webhook so it lands in the review
  // channel rather than the general feed.
  async sendReviewAlert(player: TrackedPlayer, ipCheck: IpCheckResult, banMinutes: number): Promise<void> {
    const embed = {
      color: 0xe67e22, // orange - "needs a look", not a hard red ban
      author: { name: 'WizanthiAntiVpn v2.0.0', icon_url: 'https://i.ibb.co/yFwJ3nDh/image.jpg' },
      title: '🟠 QUARANTINE — Review Needed',
      description:
        '```yaml\n' +
        `QUARANTINED (${banMinutes === 0 ? 'permanent' : banMinutes + ' min'}) — pending review\n` +
        `   ├─ Nick: ${player.nickname}\n` +
        `   ├─ ID: ${player.id}\n` +
        `   ├─ IP: ${player.ip}\n` +
        `   ├─ ISP: ${ipCheck.isp || 'Unknown'}\n` +
        `   ├─ Country: ${ipCheck.country || 'Unknown'}\n` +
        `   └─ Score: ${ipCheck.risk_score || 0}/100 (${(ipCheck.threat_level || 'low').toUpperCase()})\n` +
        '```',
      fields: [
        { name: 'Player', value: `\`${player.nickname}\``, inline: true },
        { name: 'IP', value: `\`${player.ip}\``, inline: true },
        { name: 'Duration', value: banMinutes === 0 ? 'Permanent' : `${banMinutes} min`, inline: true },
        { name: 'ISP', value: ipCheck.isp || 'Unknown', inline: true },
        { name: 'Score', value: `${ipCheck.risk_score || 0}/100`, inline: true },
        { name: 'Confidence', value: 'SOFT (review)', inline: true },
        ...(ipCheck.risk_breakdown && ipCheck.risk_breakdown.length > 0 ? [{
          name: '📊 Why',
          value: '```diff\n' + ipCheck.risk_breakdown.map(b => `${b.weight >= 0 ? '+' : ''}${b.weight} ${b.label}`).join('\n') + '\n```',
          inline: false
        }] : []),
        { name: 'Action', value: 'Auto-expires. Whitelist the IP to lift early, or blacklist it to make the ban permanent.', inline: false },
        { name: 'Server', value: `\`${this.serverAddress}\``, inline: true }
      ],
      timestamp: new Date().toISOString(),
      footer: { text: `WizanthiAntiVpn • ${this.serverAddress} • REVIEW`, icon_url: 'https://i.ibb.co/yFwJ3nDh/image.jpg' }
    };
    await this.sendEmbed(this.alertWebhook || this.mainWebhook, embed);
    this.logger.info(`Review alert sent for ${player.nickname} (${player.ip})`);
  }

  // Send embed to webhook. All posts to a given webhook are serialized and
  // spaced so we stay under Discord's ~30 req/min per-webhook cap, and any
  // 429 backs off the whole webhook (not just the one call) so a parallel
  // burst can't stampede into a repeated 429 and silently drop alerts.
  private async sendEmbed(webhook: AxiosInstance, embed: any): Promise<void> {
    return this.enqueue(webhook, () => this.postEmbed(webhook, embed));
  }

  // Lazily get (or create) the per-webhook serialization/backoff state.
  private getChannel(webhook: AxiosInstance): { chain: Promise<void>; nextAllowedAt: number } {
    let channel = this.channels.get(webhook);
    if (!channel) {
      channel = { chain: Promise.resolve(), nextAllowedAt: 0 };
      this.channels.set(webhook, channel);
    }
    return channel;
  }

  // Serialize `task` after any in-flight/queued send to the same webhook,
  // waiting out both the proactive spacing interval and any active 429
  // backoff before it runs.
  private enqueue(webhook: AxiosInstance, task: () => Promise<void>): Promise<void> {
    const channel = this.getChannel(webhook);
    const run = channel.chain.then(async () => {
      const waitMs = channel.nextAllowedAt - Date.now();
      if (waitMs > 0) await this.delay(waitMs);
      try {
        await task();
      } finally {
        // Space the next post regardless of success/failure.
        channel.nextAllowedAt = Math.max(channel.nextAllowedAt, Date.now() + WebhookService.MIN_INTERVAL_MS);
      }
    });
    // Keep the chain alive even if a task rejects, and swallow the rejection
    // on the stored tail so it isn't reported as an unhandled rejection.
    channel.chain = run.catch(() => {});
    return run;
  }

  // Perform the actual POST. Honors Discord's 429: it returns retry_after
  // telling us exactly how long to wait, which we apply to the whole
  // webhook's backoff clock (via nextAllowedAt) so every queued send waits it
  // out - then retry this one instead of dropping it.
  private async postEmbed(webhook: AxiosInstance, embed: any, attempt: number = 0): Promise<void> {
    try {
      await webhook.post('', {
        embeds: [embed],
        username: 'WizanthiAntiVpn',
        avatar_url: 'https://i.ibb.co/yFwJ3nDh/image.jpg'
      });
    } catch (error: any) {
      const status = error.response?.status;
      if (status === 429 && attempt < 3) {
        // Discord returns retry_after in seconds in the body; fall back to
        // the standard Retry-After header if absent.
        const body = error.response?.data || {};
        const retrySeconds = Number(body.retry_after ?? error.response?.headers?.['retry-after'] ?? 1);
        const waitMs = Math.min(30000, Math.max(0, retrySeconds * 1000)) + 100;
        // Back off the entire webhook, not just this retry, so concurrently
        // queued sends don't immediately trigger another 429.
        const channel = this.getChannel(webhook);
        channel.nextAllowedAt = Math.max(channel.nextAllowedAt, Date.now() + waitMs);
        this.logger.warn(`Webhook rate-limited (429), retrying in ${waitMs}ms`);
        await this.delay(waitMs);
        return this.postEmbed(webhook, embed, attempt + 1);
      }
      this.logger.error('Webhook failed', { status });
    }
  }

  // Get detection type string
  private getDetectionType(ipCheck: IpCheckResult): string {
    const types: string[] = [];
    if (ipCheck.is_datacenter) types.push('DATACENTER');
    if (ipCheck.is_vpn) types.push('VPN');
    if (ipCheck.is_proxy) types.push('PROXY');
    if (ipCheck.is_tor) types.push('TOR');
    if (ipCheck.is_hosting) types.push('HOSTING');
    return types.join(' | ') || 'UNKNOWN';
  }

  // Flush alert queue
  private async flushAlerts(): Promise<void> {
    if (this.alertQueue.length === 0) return;
    const alerts = [...this.alertQueue];
    this.alertQueue = [];
    for (const alert of alerts) {
      try { await this.sendAlertEmbed(alert); await this.delay(500); } catch (e) {}
    }
  }

  // Send individual alert embed
  private async sendAlertEmbed(alert: AlertPayload): Promise<void> {
    const colorMap: Record<string, number> = { 'info': 0x3498db, 'warning': 0xf1c40f, 'critical': 0xe74c3c };
    const embed = {
      color: colorMap[alert.severity],
      title: alert.type.toUpperCase(),
      fields: [
        ...(alert.player ? [
          { name: 'Player', value: alert.player.nickname, inline: true },
          { name: 'IP', value: `\`${alert.player.ip}\``, inline: true }
        ] : []),
        { name: 'Server', value: `\`${this.serverAddress}\``, inline: true }
      ],
      timestamp: alert.timestamp,
      footer: { text: `WizanthiAntiVpn • ${this.serverAddress}` }
    };

    await this.sendEmbed(this.alertWebhook || this.mainWebhook, embed);
  }

  // Delay helper
  private delay(ms: number): Promise<void> { return new Promise(r => setTimeout(r, ms)); }

  // Cleanup - await the final flush so queued alerts aren't lost if the
  // process exits right after this returns.
  async destroy(): Promise<void> {
    if (this.flushInterval) clearInterval(this.flushInterval);
    await this.flushAlerts();
  }
}
