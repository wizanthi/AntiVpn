# 🛡️ WizanthiAntiVpn

[Node.js](https://nodejs.org/)
[TypeScript](https://www.typescriptlang.org/)
[DDNet](https://ddnet.org/)

**DDNet Anti-Abuse Security System** — a powerful anti-VPN bot for DDNet/DDRace servers with advanced VPN, proxy, TOR, and datacenter detection.

---

## ✨ Features

- 🔍 **17 detection methods** for VPN/Proxy/TOR/Hosting
- 🧠 **Behavioral analysis** of players (GeoJump, IP changes, bot patterns)
- 📋 **Auto-updating blacklists** from 290+ sources — X4BNet, ScavengeR, TOR Exit Nodes, FireHOL Anonymous, TheSpeedX (HTTP/SOCKS4/SOCKS5), official cloud-provider ranges (AWS, GCP, Oracle, Cloudflare, DigitalOcean, Linode, Azure mirror, Fastly), and per-ASN prefix feeds for 280+ verified hosting/VPN/datacenter networks
- 🚫 **Auto-ban** mode or warning-only mode
- 🚫 **Instant ban** auto ban by isp keyword in IpChecker
- 📊 **Discord Webhook** notifications with detailed embeds
- ⚡ **IP caching** (24 hours TTL)
- 🧹 **Log Rotation & Auto-Cleanup** the bot automatically cleans up log files every X hours (configurable).
- 🔄 **Auto-reconnect** on connection loss
- 📝 **Whitelist/Blacklist** with CIDR support
- 🏢 **Anti-false-positive**: detects local ISPs, telecom providers, city networks

---

## 📋 Requirements

- **Node.js** v18 or higher
- **npm** (included with Node.js)
- **DDNet server** with RCON enabled
- **Discord Webhook** for notifications

---

## 🚀 Installation

### Windows

#### Step 1: Install Node.js

1. Download Node.js from [nodejs.org](https://nodejs.org/)
2. Choose the **LTS version** (18.x or higher)
3. Run the installer and follow the setup wizard
4. **Important:** Check the box "Automatically install the necessary tools" during installation
5. Verify installation — open **Command Prompt** or **PowerShell**:
```
node --version
npm --version
You should see version numbers (e.g., v20.11.0 and 10.2.4).

Step 2: Clone the repository
Open Command Prompt or PowerShell:

powershell
git clone https://github.com/Wizanthi/AntiVpn.git
cd AntiVpn
If you don't have Git installed, download it from git-scm.com or download the repository as ZIP from GitHub.

Step 3: Install dependencies
powershell
npm install
Step 4: Configure the bot
Open config.json in any text editor (Notepad, VS Code, etc.):

json
{
  "server": {
    "host": "127.0.0.1",
    "port": 8303,
    "rcon_password": "your_rcon_password",
    "rcon_username": "your_rcon_username"
  },
  "discord": {
    "webhook_url": "https://discord.com/api/webhooks/...",
    "alert_webhook_url": "https://discord.com/api/webhooks/..."
  },
  "bot": {
    "nickname": "WizanthiAntiVpn",
    "clan": "Security"
  },
  "auto_ban": {
    "enabled": false,
    "mode": "warn",
    "ban_duration_minutes": 10
  }
}
Step 5: Build TypeScript
powershell
npm run build
Step 6: Run the bot
powershell
npm start
To stop the bot, press Ctrl + C in the terminal.

Linux
Step 1: Install Node.js
Ubuntu/Debian:

bash
# Add NodeSource repository
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -

# Install Node.js and npm
sudo apt-get install -y nodejs

# Verify installation
node --version
npm --version
CentOS/RHEL/Fedora:

bash
# Add NodeSource repository
curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -

# Install Node.js and npm
sudo yum install -y nodejs

# Verify installation
node --version
npm --version
Arch Linux:

bash
sudo pacman -S nodejs npm
Step 2: Install Git (if not installed)
bash
# Ubuntu/Debian
sudo apt-get install -y git

# CentOS/RHEL
sudo yum install -y git

# Arch
sudo pacman -S git
Step 3: Clone the repository
bash
git clone https://github.com/Wizanthi/AntiVpn.git
cd AntiVpn
Step 4: Install dependencies
bash
npm install
Step 5: Configure the bot
Edit config.json with nano, vim, or any text editor:

bash
nano config.json
json
{
  "server": {
    "host": "127.0.0.1",
    "port": 8303,
    "rcon_password": "your_rcon_password",
    "rcon_username": "your_rcon_username"
  },
  "discord": {
    "webhook_url": "https://discord.com/api/webhooks/...",
    "alert_webhook_url": "https://discord.com/api/webhooks/..."
  },
  "bot": {
    "nickname": "WizanthiAntiVpn",
    "clan": "Security"
  },
  "auto_ban": {
    "enabled": false,
    "mode": "warn",
    "ban_duration_minutes": 10
  }
}
Save and exit (Ctrl + X, then Y, then Enter in nano).

Step 6: Build TypeScript
bash
npm run build
Step 7: Run the bot
Foreground (for testing):

bash
npm start
Press Ctrl + C to stop.

Background with screen (recommended for production):

bash
# Install screen if not installed
sudo apt-get install -y screen

# Create a new screen session
screen -S antivpn

# Start the bot
npm start

# Detach from screen: Ctrl + A, then D
# Reattach: screen -r antivpn
Background with PM2 (advanced):

bash
# Install PM2 globally
sudo npm install -g pm2

# Start the bot with PM2
pm2 start dist/index.js --name "wizanthi-antivpn" --node-args="--max-old-space-size=2048"

# Auto-start on system boot
pm2 startup
pm2 save

# View logs
pm2 logs wizanthi-antivpn

# Stop the bot
pm2 stop wizanthi-antivpn

# Restart the bot
pm2 restart wizanthi-antivpn
Background with systemd (for servers):

Create a service file:

bash
sudo nano /etc/systemd/system/wizanthi-antivpn.service
Paste the following:

ini
[Unit]
Description=Wizanthi Anti-VPN Bot
After=network.target

[Service]
Type=simple
User=your_username
WorkingDirectory=/home/your_username/AntiVpn
ExecStart=/usr/bin/node --max-old-space-size=2048 dist/index.js
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
Then enable and start:

bash
sudo systemctl daemon-reload
sudo systemctl enable wizanthi-antivpn
sudo systemctl start wizanthi-antivpn

# Check status
sudo systemctl status wizanthi-antivpn

# View logs
sudo journalctl -u wizanthi-antivpn -f
⚙️ Configuration
auto_ban modes
Mode	Description
warn	Discord notifications only, no ban
autoban	Automatic ban when VPN/proxy detected
auto_ban.enabled
true — auto-ban enabled

false — auto-ban disabled

Interval settings
Parameter	Default	Description
monitoring.status_interval_seconds	40	Status check interval
ipcheck.cache_ttl_hours	24	IP cache time-to-live
ipcheck.rate_limit_ms	1500	Delay between API requests

API keys (`apis` block)
Each entry lives under `apis.<name>.api_key` in `config.json`. Leave `api_key` empty to use only the free/keyless tier (or an env var fallback, e.g. `IPINFO_API_KEY`).

Config key	Provider	Sign up	Key format
apis.ipapi_api      ip-api.com	—	keyless, no `api_key` field
apis.ipwhois_api    ipwhois.app	—	keyless, no `api_key` field
apis.ipapico_api    ipapi.co	—	keyless, no `api_key` field
apis.ipinfo_api     ipinfo.io	ipinfo.io/signup	alphanumeric token, e.g. `12345a6789b12cde345fa67890b12345`
apis.vpnapi_api     vpnapi.io	vpnapi.io	opaque token, no fixed prefix
apis.proxycheck_api proxycheck.io	proxycheck.io	`######-######-######-######` (paid) or `public-######-######-######`
apis.ipquality_api  ipqualityscore.com	ipqualityscore.com/create-account	opaque alphanumeric string, no fixed prefix
apis.abuseipdb_api  abuseipdb.com	abuseipdb.com	long (~80 char) alphanumeric token
apis.ipapiis_api    ipapi.is	—	keyless, no `api_key` field
apis.rdap_api       rdap.org	—	keyless, no `api_key` field
apis.getipintel_api getipintel.net	getipintel.net	`api_key` holds a contact **email address**, not a token
apis.iplocate_api   iplocate.io	iplocate.io	opaque alphanumeric token, no fixed prefix
apis.ipregistry_api ipregistry.co	ipregistry.co	starts with `ira_`

🔧 Commands
Command	         Description
npm install	Install dependencies
npm run build	Build TypeScript to JavaScript
npm start	Start the bot
npm run dev	Start in development mode
🛡️ How It Works
Bot connects to the DDNet server via RCON

Every N seconds it requests the player list (status)

For each player, it checks the IP through 5+ APIs and 12 additional methods

Analyzes ISP, organization, reverse DNS, open ports, TTL, BGP, WHOIS

When VPN/proxy detected:

Warn mode: sends Discord notification

AutoBan mode: automatically bans the player

Maintains blacklist/whitelist with auto-updates every 6 hours
```
🤝 Credits
Author: [Wizanthi](https://github.com/Wizanthi)

Libraries used:

[teeworlds](https://www.npmjs.com/package/teeworlds) — DDNet client library

[axios](https://axios.rest/) — HTTP client

[winston](https://github.com/winstonjs/winston) — Logging

[TypeScript](https://www.typescriptlang.org/) — Programming language

⚠️ Disclaimer
This bot is designed to protect servers from abuse. The author is not responsible for false positives or any damage caused by the use of this software.

If you believe your IP has been blocked by mistake — contact the server administrator.

🌟 Support
GitHub Issues: [Report a bug](https://github.com/Wizanthi/AntiVpn/issues)

Contact: [@WizanthiContactBot](https://t.me/WizanthiContactBot) (Telegram)
