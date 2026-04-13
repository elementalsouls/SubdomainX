# SubdomainX

Comprehensive subdomain enumeration tool that combines **16+ passive OSINT sources**, **DNS brute forcing**, **permutation scanning**, **recursive enumeration**, and **HTTP probing** into a single fast, async-powered tool.

## Features

| Technique | Description |
|-----------|-------------|
| **Passive OSINT (16 free sources)** | crt.sh, CertSpotter, HackerTarget, AlienVault OTX, ThreatMiner, AnubisDB, URLScan, RapidDNS, WebArchive, BufferOver, DNSRepo, Shrewdeye, CommonCrawl, Digitorus, Riddler, FullHunt |
| **API-key sources (6 optional)** | VirusTotal, SecurityTrails, Shodan, Censys, BinaryEdge, ProjectDiscovery Chaos |
| **DNS Zone Transfer** | AXFR attempts against all nameservers |
| **DNS Brute Force** | High-speed async brute forcing with wildcard detection |
| **Permutation Scanning** | Generates and tests prefix/suffix combinations of discovered subdomains |
| **Recursive Enumeration** | Finds subdomains of subdomains |
| **HTTP Probing** | Resolves DNS, checks HTTP/HTTPS, extracts page titles and server headers |
| **Wildcard Detection** | Automatically detects and filters wildcard DNS to prevent false positives |

## Installation

```bash
cd SubdomainX
pip install -r requirements.txt
```

## Usage

```bash
# Basic passive + brute force
python -m subdomainx example.com

# Save results
python -m subdomainx example.com -o results.txt        # plain text
python -m subdomainx example.com -o results.json       # JSON with metadata
python -m subdomainx example.com -o results.csv        # CSV

# Full scan (all techniques)
python -m subdomainx example.com --all -o results.json

# Passive only (no brute force)
python -m subdomainx example.com --no-bruteforce

# Custom wordlist and concurrency
python -m subdomainx example.com -w /path/to/wordlist.txt -t 1000

# With HTTP probing
python -m subdomainx example.com --probe

# Individual techniques
python -m subdomainx example.com --permutations
python -m subdomainx example.com --recursive --recursive-depth 3
```

## Options

| Flag | Description |
|------|-------------|
| `-o, --output` | Output file (.txt, .json, .csv) |
| `-w, --wordlist` | Custom wordlist for brute forcing |
| `-t, --concurrency` | Concurrent DNS queries (default: 500) |
| `--no-bruteforce` | Skip DNS brute forcing |
| `--permutations` | Enable permutation scanning |
| `--recursive` | Enable recursive enumeration |
| `--recursive-depth` | Recursion depth (default: 2) |
| `--probe` | Probe HTTP/HTTPS for all results |
| `--all` | Enable all techniques |

## API Keys (Optional)

Set via environment variables or `~/.subdomainx/config.json`:

```bash
export VIRUSTOTAL_API_KEY=your_key
export SECURITYTRAILS_API_KEY=your_key
export SHODAN_API_KEY=your_key
export CENSYS_API_KEY=id:secret
export BINARYEDGE_API_KEY=your_key
export CHAOS_API_KEY=your_key
```

Or create `~/.subdomainx/config.json`:
```json
{
  "api_keys": {
    "virustotal": "your_key",
    "securitytrails": "your_key",
    "shodan": "your_key",
    "censys": "id:secret",
    "binaryedge": "your_key",
    "chaos": "your_key"
  }
}
```

## Architecture

```
SubdomainX/
├── subdomainx/
│   ├── __init__.py       # Package metadata
│   ├── __main__.py       # CLI + orchestrator
│   ├── passive.py        # 22 passive OSINT sources
│   ├── active.py         # Brute force, zone transfer, permutations, recursive
│   └── resolver.py       # DNS resolution + HTTP probing
├── wordlists/
│   └── subdomains.txt    # Built-in wordlist (~3000 entries)
├── requirements.txt
└── README.md
```

## How It Beats Other Tools

1. **More sources** — 16 free passive sources + 6 API sources queried concurrently
2. **Smart brute forcing** — Wildcard detection prevents false positives; multiple DNS resolvers for speed
3. **Permutation engine** — Discovers subdomains that brute forcing misses by combining found patterns
4. **Recursive discovery** — Automatically enumerates sub-subdomains
5. **All-in-one** — No need to chain Subfinder → Amass → HTTPX; one tool does it all
6. **Async everything** — Built on asyncio/aiohttp for maximum throughput
