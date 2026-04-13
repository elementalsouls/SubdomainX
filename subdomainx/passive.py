"""
Passive subdomain enumeration from multiple OSINT sources.
Each source is a class with an async `enumerate` method.
No API keys required for the free-tier sources.
"""

import asyncio
import re
import json
import ssl
import hashlib
import urllib.parse
from typing import Set, Optional

import aiohttp
from bs4 import BeautifulSoup


class BaseSource:
    """Base class for all passive enumeration sources."""

    name: str = "Unknown"
    timeout: int = 30

    def __init__(self, domain: str, session: aiohttp.ClientSession):
        self.domain = domain
        self.session = session
        self.results: Set[str] = set()
        self._last_error: Optional[str] = None

    async def enumerate(self) -> Set[str]:
        raise NotImplementedError

    def extract_subdomains(self, text: str) -> Set[str]:
        """Extract subdomains matching the target domain from arbitrary text."""
        pattern = r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*" + re.escape(self.domain)
        matches = re.findall(pattern, text, re.IGNORECASE)
        found = set()
        for m in matches:
            sub = m.strip().lower().lstrip(".")
            if sub.endswith(self.domain) and sub != "":
                # Remove leading wildcards or dots
                sub = sub.lstrip("*.")
                if sub:
                    found.add(sub)
        return found

    async def _get(self, url: str, headers: dict = None, params: dict = None, retries: int = 2) -> Optional[str]:
        """Perform a GET request and return response text, with retries."""
        last_err = None
        for attempt in range(retries + 1):
            try:
                h = headers or {}
                h.setdefault("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                async with self.session.get(
                    url, headers=h, params=params, timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as resp:
                    if resp.status == 200:
                        return await resp.text()
                    last_err = f"HTTP {resp.status}"
            except Exception as e:
                last_err = f"{type(e).__name__}: {e}"
                if attempt < retries:
                    await asyncio.sleep(1 * (attempt + 1))
        if last_err:
            self._last_error = last_err
        return None

    async def _get_json(self, url: str, headers: dict = None, params: dict = None, retries: int = 2):
        """Perform a GET request and return parsed JSON, with retries."""
        last_err = None
        for attempt in range(retries + 1):
            try:
                h = headers or {}
                h.setdefault("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                async with self.session.get(
                    url, headers=h, params=params, timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as resp:
                    if resp.status == 200:
                        return await resp.json(content_type=None)
                    last_err = f"HTTP {resp.status}"
            except Exception as e:
                last_err = f"{type(e).__name__}: {e}"
                if attempt < retries:
                    await asyncio.sleep(1 * (attempt + 1))
        if last_err:
            self._last_error = last_err
        return None


# ---------------------------------------------------------------------------
# Certificate Transparency Sources
# ---------------------------------------------------------------------------

class CrtSh(BaseSource):
    """crt.sh - Certificate Transparency log search."""
    name = "crt.sh"
    timeout = 90

    async def enumerate(self) -> Set[str]:
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        data = await self._get_json(url)
        if data:
            for entry in data:
                name_value = entry.get("name_value", "")
                for line in name_value.split("\n"):
                    line = line.strip().lower().lstrip("*.")
                    if line.endswith(self.domain):
                        self.results.add(line)
        return self.results


class CertSpotter(BaseSource):
    """Cert Spotter API."""
    name = "CertSpotter"

    async def enumerate(self) -> Set[str]:
        url = f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
        data = await self._get_json(url)
        if data and isinstance(data, list):
            for entry in data:
                for name in entry.get("dns_names", []):
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(self.domain):
                        self.results.add(name)
        return self.results


# ---------------------------------------------------------------------------
# DNS Aggregator Sources
# ---------------------------------------------------------------------------

class HackerTarget(BaseSource):
    """HackerTarget API - DNS lookup."""
    name = "HackerTarget"

    async def enumerate(self) -> Set[str]:
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        text = await self._get(url)
        if text and "error" not in text.lower():
            for line in text.split("\n"):
                parts = line.split(",")
                if parts:
                    host = parts[0].strip().lower()
                    if host.endswith(self.domain):
                        self.results.add(host)
        return self.results


class AlienVaultOTX(BaseSource):
    """AlienVault OTX passive DNS."""
    name = "AlienVault OTX"
    timeout = 45

    async def enumerate(self) -> Set[str]:
        page = 1
        while page <= 10:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns?page={page}"
            data = await self._get_json(url)
            if not data:
                break
            records = data.get("passive_dns", [])
            if not records:
                break
            for record in records:
                hostname = record.get("hostname", "").strip().lower()
                if hostname.endswith(self.domain):
                    self.results.add(hostname)
            if not data.get("has_next", False):
                break
            page += 1
        return self.results


class ThreatMiner(BaseSource):
    """ThreatMiner API."""
    name = "ThreatMiner"

    async def enumerate(self) -> Set[str]:
        url = f"https://api.threatminer.org/v2/domain.php?q={self.domain}&rt=5"
        data = await self._get_json(url)
        if data and data.get("results"):
            for sub in data["results"]:
                sub = sub.strip().lower()
                if sub.endswith(self.domain):
                    self.results.add(sub)
        return self.results


class AnubisDB(BaseSource):
    """Anubis DB - jldc.me API."""
    name = "AnubisDB"

    async def enumerate(self) -> Set[str]:
        url = f"https://jldc.me/anubis/subdomains/{self.domain}"
        data = await self._get_json(url)
        if data and isinstance(data, list):
            for sub in data:
                sub = sub.strip().lower()
                if sub.endswith(self.domain):
                    self.results.add(sub)
        return self.results


class URLScan(BaseSource):
    """urlscan.io search."""
    name = "URLScan"

    async def enumerate(self) -> Set[str]:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=1000"
        data = await self._get_json(url)
        if data:
            for result in data.get("results", []):
                page = result.get("page", {})
                domain = page.get("domain", "").strip().lower()
                if domain.endswith(self.domain):
                    self.results.add(domain)
        return self.results


class RapidDNS(BaseSource):
    """RapidDNS.io scraper."""
    name = "RapidDNS"

    async def enumerate(self) -> Set[str]:
        url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
        text = await self._get(url)
        if text:
            self.results = self.extract_subdomains(text)
        return self.results


class WebArchive(BaseSource):
    """Wayback Machine CDX API."""
    name = "WebArchive"
    timeout = 60

    async def enumerate(self) -> Set[str]:
        url = "https://web.archive.org/cdx/search/cdx"
        params = {
            "url": f"*.{self.domain}/*",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "limit": "10000"
        }
        data = await self._get_json(url, params=params)
        if data and isinstance(data, list):
            for entry in data[1:]:  # Skip header row
                if entry:
                    try:
                        parsed = urllib.parse.urlparse(entry[0])
                        host = parsed.hostname
                        if host and host.endswith(self.domain):
                            self.results.add(host.lower())
                    except Exception:
                        pass
        return self.results


class BufferOver(BaseSource):
    """BufferOver DNS records."""
    name = "BufferOver"

    async def enumerate(self) -> Set[str]:
        url = f"https://tls.bufferover.run/dns?q=.{self.domain}"
        data = await self._get_json(url)
        if data:
            for record in data.get("Results", []):
                parts = record.split(",")
                for part in parts:
                    part = part.strip().lower()
                    if part.endswith(self.domain):
                        self.results.add(part)
        return self.results


class DNSRepo(BaseSource):
    """dnsrepo.noc.org scraper."""
    name = "DNSRepo"

    async def enumerate(self) -> Set[str]:
        url = f"https://dnsrepo.noc.org/?domain={self.domain}"
        text = await self._get(url)
        if text:
            self.results = self.extract_subdomains(text)
        return self.results


class Shrewdeye(BaseSource):
    """shrewdeye.app subdomain source."""
    name = "Shrewdeye"

    async def enumerate(self) -> Set[str]:
        url = f"https://shrewdeye.app/domains/{self.domain}.txt"
        text = await self._get(url)
        if text:
            for line in text.strip().split("\n"):
                line = line.strip().lower()
                if line.endswith(self.domain):
                    self.results.add(line)
        return self.results


class CommonCrawl(BaseSource):
    """Common Crawl index search."""
    name = "CommonCrawl"
    timeout = 60

    async def enumerate(self) -> Set[str]:
        # Get latest index
        index_url = "https://index.commoncrawl.org/collinfo.json"
        indices = await self._get_json(index_url)
        if not indices:
            return self.results

        # Use latest index
        latest = indices[0]["cdx-api"]
        params = {
            "url": f"*.{self.domain}",
            "output": "json",
            "fl": "url",
            "limit": "5000"
        }
        text = await self._get(latest, params=params)
        if text:
            for line in text.strip().split("\n"):
                try:
                    record = json.loads(line)
                    url_str = record.get("url", "")
                    parsed = urllib.parse.urlparse(url_str)
                    host = parsed.hostname
                    if host and host.endswith(self.domain):
                        self.results.add(host.lower())
                except Exception:
                    pass
        return self.results


class Digitorus(BaseSource):
    """digitorus.com certificate search."""
    name = "Digitorus"

    async def enumerate(self) -> Set[str]:
        url = f"https://certificatedetails.com/{self.domain}"
        text = await self._get(url)
        if text:
            self.results = self.extract_subdomains(text)
        return self.results


class Riddler(BaseSource):
    """riddler.io search."""
    name = "Riddler"

    async def enumerate(self) -> Set[str]:
        url = f"https://riddler.io/search/exportcsv?q=pld:{self.domain}"
        text = await self._get(url)
        if text:
            self.results = self.extract_subdomains(text)
        return self.results


class FullHunt(BaseSource):
    """fullhunt.io search."""
    name = "FullHunt"

    async def enumerate(self) -> Set[str]:
        url = f"https://fullhunt.io/api/v1/domain/{self.domain}/subdomains"
        data = await self._get_json(url)
        if data:
            for sub in data.get("hosts", []):
                sub = sub.strip().lower()
                if sub.endswith(self.domain):
                    self.results.add(sub)
        return self.results


# ---------------------------------------------------------------------------
# API-Key Sources (optional)
# ---------------------------------------------------------------------------

class VirusTotal(BaseSource):
    """VirusTotal API (requires API key)."""
    name = "VirusTotal"

    def __init__(self, domain, session, api_key: str = None):
        super().__init__(domain, session)
        self.api_key = api_key

    async def enumerate(self) -> Set[str]:
        if not self.api_key:
            return self.results
        url = f"https://www.virustotal.com/vtapi/v2/domain/report"
        params = {"apikey": self.api_key, "domain": self.domain}
        data = await self._get_json(url, params=params)
        if data:
            for record in data.get("subdomains", []):
                sub = record.strip().lower()
                if sub.endswith(self.domain):
                    self.results.add(sub)
        return self.results


class SecurityTrails(BaseSource):
    """SecurityTrails API (requires API key)."""
    name = "SecurityTrails"

    def __init__(self, domain, session, api_key: str = None):
        super().__init__(domain, session)
        self.api_key = api_key

    async def enumerate(self) -> Set[str]:
        if not self.api_key:
            return self.results
        url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
        headers = {"APIKEY": self.api_key}
        data = await self._get_json(url, headers=headers)
        if data:
            for sub in data.get("subdomains", []):
                full = f"{sub}.{self.domain}".lower()
                self.results.add(full)
        return self.results


class Shodan(BaseSource):
    """Shodan API (requires API key)."""
    name = "Shodan"

    def __init__(self, domain, session, api_key: str = None):
        super().__init__(domain, session)
        self.api_key = api_key

    async def enumerate(self) -> Set[str]:
        if not self.api_key:
            return self.results
        url = f"https://api.shodan.io/dns/domain/{self.domain}"
        params = {"key": self.api_key}
        data = await self._get_json(url, params=params)
        if data:
            for record in data.get("subdomains", []):
                full = f"{record}.{self.domain}".lower()
                self.results.add(full)
        return self.results


class Censys(BaseSource):
    """Censys API (requires API ID + Secret)."""
    name = "Censys"

    def __init__(self, domain, session, api_id: str = None, api_secret: str = None):
        super().__init__(domain, session)
        self.api_id = api_id
        self.api_secret = api_secret

    async def enumerate(self) -> Set[str]:
        if not self.api_id or not self.api_secret:
            return self.results
        url = "https://search.censys.io/api/v2/certificates/search"
        headers = {"Accept": "application/json"}
        params = {"q": self.domain, "per_page": 100}
        try:
            auth = aiohttp.BasicAuth(self.api_id, self.api_secret)
            async with self.session.get(
                url, headers=headers, params=params, auth=auth,
                timeout=aiohttp.ClientTimeout(total=self.timeout), ssl=False
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for hit in data.get("result", {}).get("hits", []):
                        for name in hit.get("names", []):
                            name = name.strip().lower().lstrip("*.")
                            if name.endswith(self.domain):
                                self.results.add(name)
        except Exception:
            pass
        return self.results


class BinaryEdge(BaseSource):
    """BinaryEdge API (requires API key)."""
    name = "BinaryEdge"

    def __init__(self, domain, session, api_key: str = None):
        super().__init__(domain, session)
        self.api_key = api_key

    async def enumerate(self) -> Set[str]:
        if not self.api_key:
            return self.results
        url = f"https://api.binaryedge.io/v2/query/domains/subdomain/{self.domain}"
        headers = {"X-Key": self.api_key}
        data = await self._get_json(url, headers=headers)
        if data:
            for sub in data.get("events", []):
                sub = sub.strip().lower()
                if sub.endswith(self.domain):
                    self.results.add(sub)
        return self.results


class ChaosProjectDiscovery(BaseSource):
    """ProjectDiscovery Chaos API (requires API key)."""
    name = "Chaos"

    def __init__(self, domain, session, api_key: str = None):
        super().__init__(domain, session)
        self.api_key = api_key

    async def enumerate(self) -> Set[str]:
        if not self.api_key:
            return self.results
        url = f"https://dns.projectdiscovery.io/dns/{self.domain}/subdomains"
        headers = {"Authorization": self.api_key}
        data = await self._get_json(url, headers=headers)
        if data:
            for sub in data.get("subdomains", []):
                full = f"{sub}.{self.domain}".lower()
                self.results.add(full)
        return self.results


# ---------------------------------------------------------------------------
# Registry of all sources
# ---------------------------------------------------------------------------

FREE_SOURCES = [
    CrtSh, CertSpotter, HackerTarget, AlienVaultOTX, ThreatMiner,
    AnubisDB, URLScan, RapidDNS, WebArchive, BufferOver,
    DNSRepo, Shrewdeye, CommonCrawl, Digitorus, Riddler, FullHunt,
]

API_SOURCES = {
    "virustotal": VirusTotal,
    "securitytrails": SecurityTrails,
    "shodan": Shodan,
    "censys": Censys,
    "binaryedge": BinaryEdge,
    "chaos": ChaosProjectDiscovery,
}
