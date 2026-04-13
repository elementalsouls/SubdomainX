"""
DNS resolution and validation for discovered subdomains.
Resolves subdomains to IPs, checks HTTP status, detects technologies.
"""

import asyncio
import socket
from dataclasses import dataclass, field
from typing import Set, Dict, List, Optional, Tuple

import aiohttp
import dns.asyncresolver


@dataclass
class SubdomainInfo:
    """Information about a resolved subdomain."""
    subdomain: str
    ips: List[str] = field(default_factory=list)
    cnames: List[str] = field(default_factory=list)
    http_status: Optional[int] = None
    https_status: Optional[int] = None
    http_title: Optional[str] = None
    https_title: Optional[str] = None
    http_server: Optional[str] = None
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

    def __init__(self, concurrency: int = 100, check_http: bool = True):
        self.concurrency = concurrency
        self.check_http = check_http
        self.resolved: Dict[str, SubdomainInfo] = {}

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
            # DNS A records
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
            resolver.timeout = 5
            resolver.lifetime = 8

            try:
                answers = await resolver.resolve(subdomain, "A")
                info.ips = [rdata.address for rdata in answers]
                info.is_alive = True
            except Exception:
                pass

            # DNS CNAME records
            try:
                answers = await resolver.resolve(subdomain, "CNAME")
                info.cnames = [str(rdata.target).rstrip(".") for rdata in answers]
            except Exception:
                pass

            # HTTP probing
            if self.check_http and (info.ips or info.cnames):
                await self._check_http(info)

        return info

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
                except Exception:
                    pass
        except Exception:
            pass

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
