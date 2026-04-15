<div align="center">

```
   ___       _       _                       _       __  __
  / __\_   _| |__   | |__   ___  _ __ ___   (_)_ __ \ \/ /
 /__\// | | | '_ \  | '_ \ / _ \| '_ ` _ \ | | '_ \ \  /
/ \/  \ |_| | |_) | | | | | (_) | | | | | || | | | |/  \
\_____/\__,_|_.__/  |_| |_|\___/|_| |_| |_|/ |_| |_/_/\_\
                                          |__/
```

# SubdomainX

### All-in-one subdomain enumeration for serious recon

**26 free OSINT sources** · **9 API-key sources** · **110K wordlist brute force** · **200+ permutation patterns** · **Subdomain takeover detection** · **HTTP probing & tech fingerprinting**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-2.0.0-green)
![License](https://img.shields.io/badge/license-MIT-orange)
![Sources](https://img.shields.io/badge/passive%20sources-35-purple)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

</div>

---

## Why SubdomainX?

Most recon workflows require chaining 4-5 tools together: `subfinder → amass → puredns → httpx → nuclei`. **SubdomainX replaces that entire pipeline with a single command.**

```bash
python -m subdomainx target.com --deep -o results.json
```

One tool. Zero config. Passive OSINT, brute force, permutations, recursive enumeration, HTTP probing, tech detection, and subdomain takeover detection — all built in.

---

## Features

### 🔍 Passive Enumeration — 26 Free Sources

All queried concurrently with zero API keys required:

| Category | Sources |
|----------|---------|
| **Certificate Transparency** | crt.sh, crt.sh (identity/dedup), CertSpotter, Myssl, Racent |
| **DNS Aggregators** | HackerTarget, RapidDNS, DNSRepo, BufferOver, BufferOver-TLS |
| **Threat Intelligence** | AlienVault OTX, ThreatMiner, AnubisDB, URLScan |
| **Web Archives** | Wayback Machine, CommonCrawl |
| **Certificate Databases** | Digitorus, Riddler, FullHunt |
| **Subdomain Databases** | SubdomainCenter, Columbus, InternetDB (Shodan free), SiteDossier |
| **Leak & Security** | Leakix, Shrewdeye, Netlas |

### 🔑 API-Key Sources — 9 Optional

Unlock additional coverage with API keys (all optional):

| Source | Env Variable |
|--------|-------------|
| VirusTotal | `VIRUSTOTAL_API_KEY` |
| SecurityTrails | `SECURITYTRAILS_API_KEY` |
| Shodan | `SHODAN_API_KEY` |
| Censys | `CENSYS_API_KEY` (format: `id:secret`) |
| BinaryEdge | `BINARYEDGE_API_KEY` |
| ProjectDiscovery Chaos | `CHAOS_API_KEY` |
| Bevigil | `BEVIGIL_API_KEY` |
| WhoisXML API | `WHOISXMLAPI_KEY` |
| ZoomEye | `ZOOMEYE_API_KEY` |

### 💥 DNS Brute Force

- **110,000-word built-in wordlist** covering common, infrastructure, cloud, dev, and regional patterns
- **8 DNS resolver pools** (Google, Cloudflare, Quad9, OpenDNS, Verisign, CleanBrowsing, Alternate DNS, AdGuard) with random rotation to avoid rate limiting
- **A + AAAA + CNAME resolution** — catches IPv6-only and CNAME-only subdomains that other tools miss
- **Automatic wildcard detection** — queries 5 random 16-char subdomains to identify and filter wildcard DNS
- **Retry with resolver rotation** on timeout

### 🔀 Permutation Scanning — 200+ Patterns

Generates smart combinations from discovered subdomains using **8 affix categories**:

| Category | Examples |
|----------|---------|
| Environment | `dev`, `staging`, `canary`, `pentest`, `sandbox` |
| Infrastructure | `api`, `redis`, `kafka`, `grafana`, `jenkins`, `k8s` |
| Cloud | `aws`, `s3`, `lambda`, `eks`, `cloudfront`, `azure` |
| Geographic | `us-east`, `eu-west`, `fra`, `sin`, `tok` |
| Access | `internal`, `partner`, `jira`, `confluence`, `wiki` |
| State | `backup`, `failover`, `replica`, `deprecated` |
| Database | `mysql`, `postgres`, `mongo`, `clickhouse`, `airflow` |
| Numbers | `1`-`10`, `01`-`09`, `001`-`003` |

**Generation strategies:** `affix-word`, `word-affix`, `affix.word`, concatenation, hyphen-split swaps, number suffixes, and cross-combination of discovered parts.

### 🔄 Recursive Enumeration

Automatically discovers subdomains of subdomains (e.g., `staging.api.target.com` from `api.target.com`). Configurable depth (default: 2, deep mode: 3). Per-base wildcard detection prevents false positives at each recursion level.

### 🌐 HTTP Probing & Tech Fingerprinting

- Probes both **HTTP and HTTPS** with redirect following
- Extracts **page titles**, **server headers**, **status codes**
- **Technology detection** from headers: Nginx, Apache, Cloudflare, IIS, LiteSpeed, PHP, ASP.NET, Express.js, Next.js, WordPress, Drupal, Shopify, Varnish

### ⚠️ Subdomain Takeover Detection

Checks discovered subdomains against **27 known service fingerprints**:

> AWS S3 · GitHub Pages · Heroku · Shopify · Azure (16 patterns) · Netlify · Vercel · Fastly · Tumblr · Zendesk · WordPress.com · Bitbucket · Ghost · Surge.sh · Fly.io · Pantheon · Unbounce · Cargo Collective · Acquia · Canny · HelpScout · HelpJuice · Readme.io · Tilda · SmartJobBoard · Strikingly · Desk

**Two-phase detection:**
1. CNAME pattern matching against known vulnerable services
2. HTTP response body fingerprint confirmation

---

## Installation

```bash
git clone https://github.com/elementalsouls/SubdomainX.git
cd SubdomainX
pip install -r requirements.txt
```

### Requirements

- Python 3.8+
- Dependencies: `aiohttp`, `aiodns`, `dnspython`, `requests`, `beautifulsoup4`, `rich`, `tqdm`

---

## Usage

### Quick Start

```bash
# Basic scan — passive sources + brute force
python -m subdomainx target.com

# Passive only (fast, no brute force)
python -m subdomainx target.com --no-bruteforce

# Full scan with all techniques
python -m subdomainx target.com --all -o results.json

# Maximum coverage — deep mode
python -m subdomainx target.com --deep -o results.json
```

### Output Formats

```bash
python -m subdomainx target.com -o results.txt     # Plain text (one per line)
python -m subdomainx target.com -o results.json    # JSON with full metadata
python -m subdomainx target.com -o results.csv     # CSV for spreadsheets
```

### Advanced Examples

```bash
# Custom wordlist + high concurrency
python -m subdomainx target.com -w /path/to/wordlist.txt -t 1000

# Passive + HTTP probing (no brute force, fast recon)
python -m subdomainx target.com --no-bruteforce --probe

# Permutations only (on top of passive + brute force)
python -m subdomainx target.com --permutations

# Recursive with custom depth
python -m subdomainx target.com --recursive --recursive-depth 3

# Everything enabled with probe
python -m subdomainx target.com --probe --permutations --recursive -o results.json
```

---

## CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `domain` | *required* | Target domain to enumerate |
| `-o, --output` | — | Output file path (`.txt`, `.json`, or `.csv`) |
| `-w, --wordlist` | built-in 110K | Custom wordlist for brute forcing |
| `-t, --concurrency` | `500` | Concurrent DNS queries |
| `--no-bruteforce` | — | Skip DNS brute forcing (passive only) |
| `--permutations` | — | Enable permutation/alteration scanning |
| `--recursive` | — | Enable recursive subdomain enumeration |
| `--recursive-depth` | `2` | Maximum recursion depth |
| `--probe` | — | Probe HTTP/HTTPS + resolve DNS + takeover detection |
| `--all` | — | Enable all techniques (permutations + recursive + probe) |
| `--deep` | — | Deep mode: `--all` + concurrency 1000 + recursive depth 3 |
| `-v, --version` | — | Show version |

---

## Scan Modes

| Mode | Command | What It Does |
|------|---------|-------------|
| **Passive Only** | `--no-bruteforce` | 26 OSINT sources, no DNS noise |
| **Standard** | *(default)* | Passive + brute force (110K words) |
| **Full** | `--all` | Passive + brute force + permutations + recursive + probe |
| **Deep** | `--deep` | Everything at max settings (1000 concurrency, depth 3) |

---

## 6-Phase Pipeline

```
┌─────────────────────────────────────────────────────────┐
│  Phase 1: Passive OSINT (26 free + 9 API sources)       │  Always
│  Phase 2: DNS Zone Transfer (AXFR)                       │  Always
│  Phase 3: DNS Brute Force (110K wordlist)                 │  Default (skip: --no-bruteforce)
│  Phase 4: Permutation Scanning (200+ patterns)           │  --permutations
│  Phase 5: Recursive Enumeration (depth 2-3)              │  --recursive
│  Phase 6: DNS Resolution + HTTP Probe + Takeover Check   │  --probe
└─────────────────────────────────────────────────────────┘
```

Each phase feeds discovered subdomains into a shared set — later phases benefit from earlier discoveries. Permutations are generated from passive + brute force results. Recursive enumeration works on all accumulated subdomains.

---

## API Key Configuration

API keys are **optional** — the tool works out of the box with 26 free sources. Keys unlock 9 additional premium sources.

### Option 1: Environment Variables

```bash
# Linux/macOS
export VIRUSTOTAL_API_KEY=your_key
export SECURITYTRAILS_API_KEY=your_key
export SHODAN_API_KEY=your_key
export CENSYS_API_KEY=id:secret
export BINARYEDGE_API_KEY=your_key
export CHAOS_API_KEY=your_key
export BEVIGIL_API_KEY=your_key
export WHOISXMLAPI_KEY=your_key
export ZOOMEYE_API_KEY=your_key
```

```powershell
# Windows PowerShell
$env:VIRUSTOTAL_API_KEY = "your_key"
$env:SECURITYTRAILS_API_KEY = "your_key"
```

### Option 2: Config File

Create `~/.subdomainx/config.json`:

```json
{
  "api_keys": {
    "virustotal": "your_key",
    "securitytrails": "your_key",
    "shodan": "your_key",
    "censys": "id:secret",
    "binaryedge": "your_key",
    "chaos": "your_key",
    "bevigil": "your_key",
    "whoisxmlapi": "your_key",
    "zoomeye": "your_key"
  }
}
```

---

## Output Format Details

### JSON Output

```json
{
  "domain": "target.com",
  "total": 142,
  "subdomains": ["api.target.com", "mail.target.com", "..."],
  "sources": {"crt.sh": 45, "RapidDNS": 38, "...": "..."},
  "resolved": {
    "api.target.com": {
      "ips": ["1.2.3.4"],
      "ipv6s": [],
      "cnames": [],
      "http_status": 200,
      "https_status": 200,
      "title": "API Documentation",
      "server": "nginx/1.24.0",
      "technologies": ["Nginx", "Cloudflare"],
      "takeover_vulnerable": false,
      "takeover_service": null,
      "alive": true
    }
  }
}
```

### CSV Output

```
Subdomain,IPs,IPv6s,CNAMEs,HTTP,HTTPS,Title,Server,Technologies,Takeover,TakeoverService,Alive
api.target.com,1.2.3.4,,, 200,200,API Docs,nginx,Nginx|Cloudflare,False,,True
```

---

## Architecture

```
SubdomainX/
├── subdomainx/
│   ├── __init__.py        # Package version
│   ├── __main__.py        # CLI entry point + 6-phase orchestrator
│   ├── passive.py         # 35 passive OSINT source classes (26 free + 9 API)
│   ├── active.py          # Brute force, zone transfer, permutations, recursive
│   └── resolver.py        # DNS resolution, HTTP probing, tech detection, takeover checks
├── wordlists/
│   └── subdomains.txt     # Built-in wordlist (~110K entries)
├── requirements.txt
└── README.md
```

---

## How It Compares

| Capability | Subfinder | Amass | SubdomainX |
|---|---|---|---|
| Free passive sources | ~15 | ~20 | **26** |
| API sources | ~25 | ~30 | 9 |
| DNS brute force | ✗ (need puredns) | ✓ | **✓ + wildcard filter + AAAA/CNAME** |
| Permutation scanning | ✗ (need altdns) | Basic | **200+ patterns, 8 categories** |
| Recursive enumeration | ✗ | ✓ | **✓ with per-base wildcard detection** |
| HTTP probing | ✗ (need httpx) | ✗ (need httpx) | **✓ built-in** |
| Tech fingerprinting | ✗ (need httpx) | ✗ | **✓ built-in** |
| Subdomain takeover | ✗ (need nuclei) | ✗ | **✓ 27 service fingerprints** |
| Single command | ✗ | Partially | **✓** |
| Zero config needed | ✗ | ✗ | **✓** |
| Language | Go | Go | Python |

**Where Go tools win:** Raw throughput for brute forcing 10M+ wordlists across thousands of targets. For most single-target engagements, the difference is negligible.

**Where SubdomainX wins:** One tool replaces a 4-5 tool pipeline. Works out of the box. Easy to extend in Python. Built-in takeover detection and tech fingerprinting.

---

## Legal Disclaimer

This tool is intended for **authorized security testing and bug bounty programs only**. Always ensure you have explicit permission before enumerating subdomains of any target. Unauthorized reconnaissance may violate applicable laws.

---

## Contributing

Pull requests welcome. To add a new passive source, create a class inheriting `BaseSource` in `passive.py` with a `name` attribute and an `async enumerate()` method returning `Set[str]`, then add it to the `FREE_SOURCES` list.

---

## License

MIT

---

<div align="center">

**Built for recon. Powered by Python.**

</div>
