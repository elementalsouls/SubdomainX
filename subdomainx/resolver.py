"""
DNS resolution and validation for discovered subdomains.
Resolves subdomains to IPs, checks HTTP status, detects technologies.
Includes subdomain takeover detection via CNAME fingerprinting.
"""

import asyncio
import socket
from dataclasses import dataclass, field
from typing import Set, Dict, List, Optional, Tuple

import aiohttp
import dns.asyncresolver


# Known CNAME fingerprints for subdomain takeover detection
TAKEOVER_FINGERPRINTS = {
    # Service: (cname_patterns, response_fingerprints)
    "AWS S3": {
        "cnames": [".s3.amazonaws.com", ".s3-website"],
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
    },
    "GitHub Pages": {
        "cnames": [".github.io", "github.map.fastly.net"],
        "fingerprints": ["There isn't a GitHub Pages site here", "For root URLs"],
    },
    "Heroku": {
        "cnames": [".herokuapp.com", ".herokussl.com", ".herokudns.com"],
        "fingerprints": ["No such app", "no-such-app", "herokucdn.com/error-pages"],
    },
    "Shopify": {
        "cnames": [".myshopify.com", "shops.myshopify.com"],
        "fingerprints": ["Sorry, this shop is currently unavailable", "Only one step left"],
    },
    "Tumblr": {
        "cnames": [".tumblr.com", "domains.tumblr.com"],
        "fingerprints": ["There's nothing here", "Whatever you were looking for doesn't currently exist"],
    },
    "Azure": {
        "cnames": [".azurewebsites.net", ".cloudapp.net", ".cloudapp.azure.com",
                   ".azure-api.net", ".azurehdinsight.net", ".azureedge.net",
                   ".azurecontainer.io", ".database.windows.net", ".azuredatalakestore.net",
                   ".search.windows.net", ".azurecr.io", ".redis.cache.windows.net",
                   ".azurehdinsight.net", ".servicebus.windows.net", ".visualstudio.com",
                   ".trafficmanager.net"],
        "fingerprints": ["404 Web Site not found", "Azure Web App - Your landing page"],
    },
    "Fastly": {
        "cnames": [".fastly.net", ".fastlylb.net", ".map.fastly.net"],
        "fingerprints": ["Fastly error: unknown domain"],
    },
    "Pantheon": {
        "cnames": [".pantheonsite.io"],
        "fingerprints": ["The gods are wise", "404 error unknown site"],
    },
    "Zendesk": {
        "cnames": [".zendesk.com"],
        "fingerprints": ["Help Center Closed", "this help center no longer exists"],
    },
    "Unbounce": {
        "cnames": [".unbounce.com", "unbouncepages.com"],
        "fingerprints": ["The requested URL was not found on this server", "The page you were looking for doesn't exist"],
    },
    "WordPress.com": {
        "cnames": [".wordpress.com"],
        "fingerprints": ["Do you want to register"],
    },
    "Surge.sh": {
        "cnames": [".surge.sh"],
        "fingerprints": ["project not found"],
    },
    "Bitbucket": {
        "cnames": [".bitbucket.io"],
        "fingerprints": ["Repository not found"],
    },
    "Ghost": {
        "cnames": [".ghost.io"],
        "fingerprints": ["The thing you were looking for is no longer here"],
    },
    "Netlify": {
        "cnames": [".netlify.app", ".netlify.com", ".bitballoon.com"],
        "fingerprints": ["Not Found - Request ID"],
    },
    "Fly.io": {
        "cnames": [".fly.dev"],
        "fingerprints": ["404 Not Found"],
    },
    "Vercel": {
        "cnames": [".vercel.app", ".now.sh", "cname.vercel-dns.com"],
        "fingerprints": ["The deployment you are trying to access"],
    },
    "Cargo Collective": {
        "cnames": [".cargocollective.com"],
        "fingerprints": ["404 Not Found"],
    },
    "Acquia": {
        "cnames": [".acquia-test.co"],
        "fingerprints": ["Web Site Not Found", "The site you are looking for could not be found"],
    },
    "Canny": {
        "cnames": [".canny.io"],
        "fingerprints": ["Company Not Found", "There is no such company"],
    },
    "HelpScout": {
        "cnames": [".helpscoutdocs.com"],
        "fingerprints": ["No settings were found for this company"],
    },
    "HelpJuice": {
        "cnames": [".helpjuice.com"],
        "fingerprints": ["We could not find what you're looking for"],
    },
    "Readme.io": {
        "cnames": [".readme.io"],
        "fingerprints": ["Project doesnt exist"],
    },
    "Tilda": {
        "cnames": [".tilda.ws"],
        "fingerprints": ["Please renew your subscription"],
    },
    "SmartJobBoard": {
        "cnames": [".smartjobboard.com"],
        "fingerprints": ["This job board website is either expired"],
    },
    "Strikingly": {
        "cnames": [".strikinglydns.com", ".s.strikinglydns.com"],
        "fingerprints": ["But if you're looking to build your own website", "page not found"],
    },
    "Desk": {
        "cnames": [".desk.com"],
        "fingerprints": ["Please try again or try Desk.com free", "Sorry, We Couldn't Find That Page"],
    },
}


@dataclass
class SubdomainInfo:
    """Information about a resolved subdomain."""
    subdomain: str
    ips: List[str] = field(default_factory=list)
    ipv6s: List[str] = field(default_factory=list)
    cnames: List[str] = field(default_factory=list)
    http_status: Optional[int] = None
    https_status: Optional[int] = None
    http_title: Optional[str] = None
    https_title: Optional[str] = None
    http_server: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    takeover_vulnerable: bool = False
    takeover_service: Optional[str] = None
    is_alive: bool = False

    @property
    def status_str(self) -> str:
        parts = []
        if self.http_status:
            parts.append(f"HTTP:{self.http_status}")
        if self.https_status:
            parts.append(f"HTTPS:{self.https_status}")
        return " | ".join(parts) if parts else "N/A"

    @property
    def title(self) -> str:
        return self.https_title or self.http_title or ""


class SubdomainResolver:
    """Resolve and validate discovered subdomains."""

    def __init__(self, concurrency: int = 100, check_http: bool = True, check_takeover: bool = True):
        self.concurrency = concurrency
        self.check_http = check_http
        self.check_takeover = check_takeover
        self.resolved: Dict[str, SubdomainInfo] = {}
        self._resolvers: List[dns.asyncresolver.Resolver] = []
        self._setup_resolvers()

    def _setup_resolvers(self):
        """Create multiple resolver instances for the resolution phase."""
        dns_servers = [
            ["8.8.8.8", "8.8.4.4"],
            ["1.1.1.1", "1.0.0.1"],
            ["9.9.9.9", "149.112.112.112"],
            ["208.67.222.222", "208.67.220.220"],
        ]
        import random
        for servers in dns_servers:
            r = dns.asyncresolver.Resolver()
            r.nameservers = servers
            r.timeout = 5
            r.lifetime = 8
            self._resolvers.append(r)

    def _get_resolver(self) -> dns.asyncresolver.Resolver:
        import random
        return random.choice(self._resolvers)

    async def resolve_all(self, subdomains: Set[str]) -> Dict[str, SubdomainInfo]:
        """Resolve all subdomains and optionally check HTTP."""
        semaphore = asyncio.Semaphore(self.concurrency)
        tasks = [self._resolve_one(sub, semaphore) for sub in subdomains]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, SubdomainInfo):
                self.resolved[result.subdomain] = result

        return self.resolved

    async def _resolve_one(self, subdomain: str, semaphore: asyncio.Semaphore) -> SubdomainInfo:
        """Resolve a single subdomain."""
        info = SubdomainInfo(subdomain=subdomain)

        async with semaphore:
            resolver = self._get_resolver()

            # DNS A records
            try:
                answers = await resolver.resolve(subdomain, "A")
                info.ips = [rdata.address for rdata in answers]
                info.is_alive = True
            except Exception:
                pass

            # DNS AAAA records
            try:
                answers = await resolver.resolve(subdomain, "AAAA")
                info.ipv6s = [rdata.address for rdata in answers]
                if info.ipv6s:
                    info.is_alive = True
            except Exception:
                pass

            # DNS CNAME records
            try:
                answers = await resolver.resolve(subdomain, "CNAME")
                info.cnames = [str(rdata.target).rstrip(".") for rdata in answers]
                if info.cnames and not info.ips:
                    info.is_alive = True
            except Exception:
                pass

            # Subdomain takeover check via CNAME fingerprints
            if self.check_takeover and info.cnames:
                self._check_takeover_cname(info)

            # HTTP probing
            if self.check_http and (info.ips or info.cnames or info.ipv6s):
                await self._check_http(info)

                # Deeper takeover check via HTTP response body
                if self.check_takeover and info.cnames:
                    self._check_takeover_http(info)

        return info

    def _check_takeover_cname(self, info: SubdomainInfo):
        """Check CNAME targets against known takeover fingerprints."""
        for cname in info.cnames:
            cname_lower = cname.lower()
            for service, data in TAKEOVER_FINGERPRINTS.items():
                for pattern in data["cnames"]:
                    if pattern.lower() in cname_lower:
                        # If CNAME points to a known service, mark as potential
                        # The HTTP check will confirm if it's actually vulnerable
                        info.takeover_service = service
                        return

    def _check_takeover_http(self, info: SubdomainInfo):
        """Cross-check HTTP response body against takeover fingerprints."""
        if not info.takeover_service:
            return
        service_data = TAKEOVER_FINGERPRINTS.get(info.takeover_service, {})
        body = (info.http_title or "") + " " + (info.https_title or "")
        # Also check via the _last_body attribute if we stored it
        response_body = getattr(info, '_response_body', '') or ''
        full_text = body + " " + response_body
        for fingerprint in service_data.get("fingerprints", []):
            if fingerprint.lower() in full_text.lower():
                info.takeover_vulnerable = True
                return

    async def _check_http(self, info: SubdomainInfo):
        """Check HTTP/HTTPS status of a subdomain."""
        timeout = aiohttp.ClientTimeout(total=10)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Check HTTPS first
                try:
                    async with session.get(
                        f"https://{info.subdomain}",
                        ssl=False,
                        allow_redirects=True,
                        max_redirects=3,
                    ) as resp:
                        info.https_status = resp.status
                        info.http_server = resp.headers.get("Server", "")
                        text = await resp.text(errors="ignore")
                        info.https_title = self._extract_title(text)
                        info.is_alive = True
                        # Store for takeover detection
                        info._response_body = text[:2000]
                        # Extract technologies from headers
                        self._detect_tech(info, resp.headers)
                except Exception:
                    pass

                # Check HTTP
                try:
                    async with session.get(
                        f"http://{info.subdomain}",
                        allow_redirects=True,
                        max_redirects=3,
                    ) as resp:
                        info.http_status = resp.status
                        if not info.http_server:
                            info.http_server = resp.headers.get("Server", "")
                        text = await resp.text(errors="ignore")
                        info.http_title = self._extract_title(text)
                        info.is_alive = True
                        if not hasattr(info, '_response_body') or not info._response_body:
                            info._response_body = text[:2000]
                        if not info.technologies:
                            self._detect_tech(info, resp.headers)
                except Exception:
                    pass
        except Exception:
            pass

    @staticmethod
    def _detect_tech(info: SubdomainInfo, headers):
        """Detect technologies from HTTP headers."""
        tech = []
        server = headers.get("Server", "").lower()
        powered_by = headers.get("X-Powered-By", "").lower()
        via = headers.get("Via", "").lower()

        if "nginx" in server:
            tech.append("Nginx")
        if "apache" in server:
            tech.append("Apache")
        if "cloudflare" in server or "cloudflare" in (headers.get("cf-ray", "")):
            tech.append("Cloudflare")
        if "microsoft" in server or "iis" in server:
            tech.append("IIS")
        if "litespeed" in server:
            tech.append("LiteSpeed")
        if "gunicorn" in server:
            tech.append("Gunicorn")
        if "express" in powered_by:
            tech.append("Express.js")
        if "php" in powered_by:
            tech.append("PHP")
        if "asp.net" in powered_by:
            tech.append("ASP.NET")
        if "next.js" in powered_by:
            tech.append("Next.js")
        if "varnish" in via:
            tech.append("Varnish")
        if headers.get("X-Drupal-Cache"):
            tech.append("Drupal")
        if "wp-" in headers.get("Link", ""):
            tech.append("WordPress")
        if headers.get("X-Shopify-Stage"):
            tech.append("Shopify")

        info.technologies = tech

    @staticmethod
    def _extract_title(html: str) -> Optional[str]:
        """Extract page title from HTML."""
        try:
            start = html.lower().find("<title>")
            if start == -1:
                return None
            start += 7
            end = html.lower().find("</title>", start)
            if end == -1:
                return None
            title = html[start:end].strip()
            # Clean up whitespace
            title = " ".join(title.split())
            return title[:100] if title else None
        except Exception:
            return None
