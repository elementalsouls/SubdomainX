"""
Active subdomain enumeration techniques:
- DNS brute forcing with wordlists
- DNS zone transfer attempts
- Permutation / alteration scanning
- Recursive subdomain enumeration
"""

import asyncio
import itertools
import random
import string
from pathlib import Path
from typing import Set, List, Callable, Optional

import dns.asyncresolver
import dns.resolver
import dns.zone
import dns.query
import dns.name
import dns.rdatatype


class WildcardDetector:
    """Detects wildcard DNS records to avoid false positives."""

    def __init__(self, domain: str):
        self.domain = domain
        self.wildcard_ips: Set[str] = set()
        self.has_wildcard = False

    async def detect(self):
        """Check if the domain has wildcard DNS by querying random subdomains."""
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        random_subs = [
            "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
            for _ in range(5)
        ]

        wildcard_ips = []
        for sub in random_subs:
            fqdn = f"{sub}.{self.domain}"
            try:
                answers = await resolver.resolve(fqdn, "A")
                ips = {rdata.address for rdata in answers}
                wildcard_ips.append(ips)
            except Exception:
                wildcard_ips.append(set())

        # If all random subdomains resolve to the same IPs, it's a wildcard
        non_empty = [s for s in wildcard_ips if s]
        if len(non_empty) >= 3:
            common = non_empty[0]
            for s in non_empty[1:]:
                common = common & s
            if common:
                self.has_wildcard = True
                self.wildcard_ips = common

        return self.has_wildcard, self.wildcard_ips

    def is_wildcard(self, ips: Set[str]) -> bool:
        """Check if a set of IPs matches the wildcard response."""
        if not self.has_wildcard:
            return False
        return bool(ips & self.wildcard_ips)


class ZoneTransfer:
    """Attempt DNS zone transfers (AXFR) against nameservers."""

    name = "ZoneTransfer"

    def __init__(self, domain: str):
        self.domain = domain

    async def enumerate(self) -> Set[str]:
        results = set()
        try:
            ns_records = dns.resolver.resolve(self.domain, "NS")
            nameservers = [str(ns.target).rstrip(".") for ns in ns_records]
        except Exception:
            return results

        for ns in nameservers:
            try:
                # Resolve NS to IP
                ns_ip = str(dns.resolver.resolve(ns, "A")[0])
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain, timeout=10))
                for name, node in zone.nodes.items():
                    subdomain = str(name)
                    if subdomain != "@":
                        fqdn = f"{subdomain}.{self.domain}".lower()
                        results.add(fqdn)
            except Exception:
                continue

        return results


class DNSBruteForcer:
    """High-performance async DNS brute forcer with wildcard filtering."""

    def __init__(
        self,
        domain: str,
        wordlist_path: str,
        wildcard_detector: WildcardDetector,
        concurrency: int = 500,
        callback: Callable = None,
    ):
        self.domain = domain
        self.wordlist_path = wordlist_path
        self.wildcard = wildcard_detector
        self.concurrency = concurrency
        self.callback = callback
        self.results: Set[str] = set()
        self._resolvers: List[dns.asyncresolver.Resolver] = []
        self._setup_resolvers()

    def _setup_resolvers(self):
        """Create multiple resolver instances for load balancing."""
        # Public DNS servers for high-throughput resolution
        dns_servers = [
            ["8.8.8.8", "8.8.4.4"],          # Google
            ["1.1.1.1", "1.0.0.1"],          # Cloudflare
            ["9.9.9.9", "149.112.112.112"],  # Quad9
            ["208.67.222.222", "208.67.220.220"],  # OpenDNS
            ["64.6.64.6", "64.6.65.6"],      # Verisign
        ]
        for servers in dns_servers:
            r = dns.asyncresolver.Resolver()
            r.nameservers = servers
            r.timeout = 3
            r.lifetime = 5
            self._resolvers.append(r)

    def _get_resolver(self) -> dns.asyncresolver.Resolver:
        return random.choice(self._resolvers)

    async def _resolve_one(self, subdomain: str, semaphore: asyncio.Semaphore) -> Optional[str]:
        """Resolve a single subdomain."""
        fqdn = f"{subdomain}.{self.domain}"
        async with semaphore:
            resolver = self._get_resolver()
            try:
                answers = await resolver.resolve(fqdn, "A")
                ips = {rdata.address for rdata in answers}
                if not self.wildcard.is_wildcard(ips):
                    return fqdn
            except (dns.asyncresolver.NXDOMAIN, dns.asyncresolver.NoAnswer,
                    dns.asyncresolver.NoNameservers, asyncio.TimeoutError,
                    dns.exception.Timeout, Exception):
                pass
        return None

    def _load_wordlist(self) -> List[str]:
        """Load subdomain wordlist from file."""
        words = []
        path = Path(self.wordlist_path)
        if not path.exists():
            return words
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip().lower()
                if word and not word.startswith("#"):
                    words.append(word)
        return words

    async def brute_force(self) -> Set[str]:
        """Run DNS brute force against the wordlist."""
        words = self._load_wordlist()
        if not words:
            return self.results

        semaphore = asyncio.Semaphore(self.concurrency)
        tasks = [self._resolve_one(word, semaphore) for word in words]

        # Process in batches for progress tracking
        batch_size = 1000
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i : i + batch_size]
            results = await asyncio.gather(*batch, return_exceptions=True)
            for result in results:
                if isinstance(result, str) and result:
                    self.results.add(result)
                    if self.callback:
                        self.callback(result)

        return self.results


class PermutationScanner:
    """Generate and test subdomain permutations based on discovered subdomains."""

    def __init__(
        self,
        domain: str,
        found_subdomains: Set[str],
        wildcard_detector: WildcardDetector,
        concurrency: int = 300,
        callback: Callable = None,
    ):
        self.domain = domain
        self.found = found_subdomains
        self.wildcard = wildcard_detector
        self.concurrency = concurrency
        self.callback = callback
        self.results: Set[str] = set()
        self._resolvers: List[dns.asyncresolver.Resolver] = []
        self._setup_resolvers()

    def _setup_resolvers(self):
        dns_servers = [
            ["8.8.8.8", "8.8.4.4"],
            ["1.1.1.1", "1.0.0.1"],
            ["9.9.9.9", "149.112.112.112"],
        ]
        for servers in dns_servers:
            r = dns.asyncresolver.Resolver()
            r.nameservers = servers
            r.timeout = 3
            r.lifetime = 5
            self._resolvers.append(r)

    def _generate_permutations(self) -> Set[str]:
        """Generate permutations of discovered subdomains."""
        permutations = set()

        # Extract subdomain parts (without the base domain)
        parts = set()
        for sub in self.found:
            prefix = sub.replace(f".{self.domain}", "")
            if prefix:
                parts.add(prefix)

        # Common prefixes/suffixes to combine
        affixes = [
            "dev", "staging", "stage", "stg", "test", "testing", "qa",
            "uat", "prod", "production", "pre", "preprod", "demo",
            "beta", "alpha", "v1", "v2", "v3", "api", "app", "web",
            "www", "mail", "email", "admin", "portal", "internal",
            "external", "public", "private", "new", "old", "backup",
            "bak", "temp", "tmp", "dr", "sandbox", "lab",
            "1", "2", "3", "01", "02", "03",
        ]

        for part in parts:
            for affix in affixes:
                # prefix-word, word-prefix
                permutations.add(f"{affix}-{part}")
                permutations.add(f"{part}-{affix}")
                permutations.add(f"{affix}{part}")
                permutations.add(f"{part}{affix}")
                permutations.add(f"{affix}.{part}")
                permutations.add(f"{part}.{affix}")

        # Remove already-known subdomains
        known_prefixes = {sub.replace(f".{self.domain}", "") for sub in self.found}
        permutations -= known_prefixes

        return permutations

    async def _resolve_one(self, prefix: str, semaphore: asyncio.Semaphore) -> Optional[str]:
        fqdn = f"{prefix}.{self.domain}"
        async with semaphore:
            resolver = random.choice(self._resolvers)
            try:
                answers = await resolver.resolve(fqdn, "A")
                ips = {rdata.address for rdata in answers}
                if not self.wildcard.is_wildcard(ips):
                    return fqdn
            except Exception:
                pass
        return None

    async def scan(self) -> Set[str]:
        """Run permutation scanning."""
        perms = self._generate_permutations()
        if not perms:
            return self.results

        semaphore = asyncio.Semaphore(self.concurrency)
        tasks = [self._resolve_one(p, semaphore) for p in perms]

        batch_size = 1000
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i : i + batch_size]
            results = await asyncio.gather(*batch, return_exceptions=True)
            for result in results:
                if isinstance(result, str) and result:
                    self.results.add(result)
                    if self.callback:
                        self.callback(result)

        return self.results


class RecursiveEnumerator:
    """Recursively enumerate subdomains of discovered subdomains."""

    def __init__(
        self,
        domain: str,
        found_subdomains: Set[str],
        wordlist_path: str,
        wildcard_detector: WildcardDetector,
        concurrency: int = 300,
        max_depth: int = 2,
        callback: Callable = None,
    ):
        self.domain = domain
        self.found = found_subdomains
        self.wordlist_path = wordlist_path
        self.wildcard = wildcard_detector
        self.concurrency = concurrency
        self.max_depth = max_depth
        self.callback = callback
        self.results: Set[str] = set()

    async def enumerate(self) -> Set[str]:
        """Run recursive brute force against discovered subdomains."""
        # Only recurse on subdomains that are one level deep
        candidates = set()
        for sub in self.found:
            prefix = sub.replace(f".{self.domain}", "")
            parts = prefix.split(".")
            if len(parts) == 1 and parts[0]:
                candidates.add(sub)

        # Use a smaller wordlist for recursive enumeration
        small_words = self._load_small_wordlist()
        if not small_words or not candidates:
            return self.results

        for base_sub in candidates:
            wc = WildcardDetector(base_sub)
            await wc.detect()

            semaphore = asyncio.Semaphore(self.concurrency)
            tasks = []
            for word in small_words:
                fqdn = f"{word}.{base_sub}"
                tasks.append(self._resolve(fqdn, wc, semaphore))

            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, str) and result:
                    self.results.add(result)
                    if self.callback:
                        self.callback(result)

        return self.results

    def _load_small_wordlist(self) -> List[str]:
        """Load a subset of the wordlist for recursive enumeration."""
        path = Path(self.wordlist_path)
        if not path.exists():
            return []
        words = []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip().lower()
                if word and not word.startswith("#"):
                    words.append(word)
                if len(words) >= 500:  # Limit for recursive
                    break
        return words

    async def _resolve(self, fqdn: str, wc: WildcardDetector, sem: asyncio.Semaphore) -> Optional[str]:
        async with sem:
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
            resolver.timeout = 3
            resolver.lifetime = 5
            try:
                answers = await resolver.resolve(fqdn, "A")
                ips = {rdata.address for rdata in answers}
                if not wc.is_wildcard(ips):
                    return fqdn
            except Exception:
                pass
        return None
