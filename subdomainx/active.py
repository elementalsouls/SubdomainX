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

from .mutations import generate_mutations, STATIC_AFFIXES, DEFAULT_MAX_MUTATIONS


class WildcardDetector:
    """Detects wildcard DNS to avoid false positives — apex AND per-parent, and
    CNAME-wildcard aware. One instance is reused across phases (a per-parent cache
    means each parent is probed once, not once per phase or per candidate)."""

    def __init__(self, domain: str):
        self.domain = domain
        self.wildcard_ips: Set[str] = set()
        self.wildcard_cnames: Set[str] = set()
        self.has_wildcard = False
        # parent -> (has_wildcard, ip_set, cname_set)
        self._cache: dict = {}

    async def _probe(self, parent: str):
        """Query several random labels under *parent* for A + CNAME. Returns the
        per-probe ip-sets and cname-sets."""
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        ip_sets: List[Set[str]] = []
        cname_sets: List[Set[str]] = []
        for _ in range(5):
            sub = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
            fqdn = f"{sub}.{parent}"
            ips: Set[str] = set()
            cnames: Set[str] = set()
            try:
                for rdata in await resolver.resolve(fqdn, "A"):
                    ips.add(rdata.address)
            except Exception:
                pass
            try:
                for rdata in await resolver.resolve(fqdn, "CNAME"):
                    cnames.add(str(rdata.target).rstrip("."))
            except Exception:
                pass
            ip_sets.append(ips)
            cname_sets.append(cnames)
        return ip_sets, cname_sets

    @staticmethod
    def _common(sets: List[Set[str]]) -> Set[str]:
        non_empty = [s for s in sets if s]
        if len(non_empty) < 3:
            return set()
        common = set(non_empty[0])
        for s in non_empty[1:]:
            common &= s
        return common

    async def detect_parent(self, parent: str):
        """Per-parent wildcard detection (cached). Returns
        ``(has_wildcard, ip_set, cname_set)`` for *parent*."""
        if parent in self._cache:
            return self._cache[parent]
        ip_sets, cname_sets = await self._probe(parent)
        common_ips = self._common(ip_sets)
        common_cnames = self._common(cname_sets)
        result = (bool(common_ips or common_cnames), common_ips, common_cnames)
        self._cache[parent] = result
        return result

    async def detect(self):
        """Detect the apex wildcard (back-compat entry point). Populates
        ``has_wildcard`` / ``wildcard_ips`` / ``wildcard_cnames``."""
        has, ips, cnames = await self.detect_parent(self.domain)
        self.has_wildcard = has
        self.wildcard_ips = ips
        self.wildcard_cnames = cnames
        return self.has_wildcard, self.wildcard_ips

    def is_wildcard(self, ips: Set[str], cnames: Optional[Set[str]] = None) -> bool:
        """True if the answer matches the (apex) wildcard — by IP or, when the
        wildcard is a CNAME wildcard, by CNAME target."""
        if self.has_wildcard and ips and (set(ips) & self.wildcard_ips):
            return True
        if cnames and self.wildcard_cnames and (set(cnames) & self.wildcard_cnames):
            return True
        return False

    @staticmethod
    def is_junk(name: str) -> bool:
        """Drop PTR-like / excessive-digit names (e.g. ``10-20-30-40.example.com``)
        before they enter the mutation corpus or results."""
        from .mutations import has_excessive_digits
        label = (name or "").split(".")[0].lower()
        return not label or has_excessive_digits(label)


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
        # Optional bulk resolver backend (a MassdnsResolver). None => per-name
        # dnspython via _resolve_one. Attr-injected (like max_words) so the frozen
        # __init__ signature the Falcon adapter monkeypatches stays intact.
        self.resolver_backend = None
        self._resolvers: List[dns.asyncresolver.Resolver] = []
        self._setup_resolvers()

    async def bulk_resolve(self, words) -> Set[str]:
        """Resolve candidate *words* (subdomain prefixes) against ``self.domain``.

        Uses the attached massdns backend for a single bulk pass when present +
        usable; otherwise falls back to per-name dnspython through ``_resolve_one``
        (which the Falcon adapter patches for live progress). Adds every hit to
        ``self.results`` and fires ``self.callback``."""
        words = [w for w in words if w]
        if not words:
            return set()
        backend = getattr(self, "resolver_backend", None)
        if backend is not None and getattr(backend, "binary", None):
            wc_ips = (self.wildcard.wildcard_ips
                      if getattr(self.wildcard, "has_wildcard", False) else set())
            fqdns = [f"{w}.{self.domain}" for w in words]
            records = await backend.resolve(fqdns, wildcard_ips=wc_ips)
            hits = set(records.keys())
            for h in hits:
                self.results.add(h)
                if self.callback:
                    self.callback(h)
            return hits
        # dnspython fallback — per-name, honours the (possibly patched) _resolve_one
        semaphore = asyncio.Semaphore(self.concurrency)
        tasks = [self._resolve_one(w, semaphore) for w in words]
        hits: Set[str] = set()
        for i in range(0, len(tasks), 1000):
            batch = tasks[i:i + 1000]
            for r in await asyncio.gather(*batch, return_exceptions=True):
                if isinstance(r, str) and r:
                    hits.add(r)
                    self.results.add(r)
                    if self.callback:
                        self.callback(r)
        return hits

    def _setup_resolvers(self):
        """Create multiple resolver instances for load balancing."""
        # Public DNS servers for high-throughput resolution
        dns_servers = [
            ["8.8.8.8", "8.8.4.4"],                    # Google
            ["1.1.1.1", "1.0.0.1"],                    # Cloudflare
            ["9.9.9.9", "149.112.112.112"],             # Quad9
            ["208.67.222.222", "208.67.220.220"],       # OpenDNS
            ["64.6.64.6", "64.6.65.6"],                # Verisign
            ["185.228.168.9", "185.228.169.9"],         # CleanBrowsing
            ["76.76.19.19", "76.223.122.150"],          # Alternate DNS
            ["94.140.14.14", "94.140.15.15"],           # AdGuard DNS
        ]
        for servers in dns_servers:
            r = dns.asyncresolver.Resolver()
            r.nameservers = servers
            r.timeout = 1.5
            r.lifetime = 2.5
            self._resolvers.append(r)

    def _get_resolver(self) -> dns.asyncresolver.Resolver:
        return random.choice(self._resolvers)

    async def _resolve_one(self, subdomain: str, semaphore: asyncio.Semaphore) -> Optional[str]:
        """Resolve a single subdomain. Checks A, AAAA, and CNAME records."""
        fqdn = f"{subdomain}.{self.domain}"
        async with semaphore:
            # Try A record first
            resolver = self._get_resolver()
            try:
                answers = await resolver.resolve(fqdn, "A")
                ips = {rdata.address for rdata in answers}
                if not self.wildcard.is_wildcard(ips):
                    return fqdn
            except (dns.asyncresolver.NXDOMAIN, dns.asyncresolver.NoNameservers):
                return None
            except (dns.asyncresolver.NoAnswer,):
                pass  # No A record, try AAAA/CNAME below
            except (asyncio.TimeoutError, dns.exception.Timeout):
                # A record timeout — don't chase AAAA/CNAME, just bail. Saves ~5s per
                # failing word, which is the common case on bruteforce.
                return None
            except Exception:
                return None

            # Try AAAA (only if A returned NoAnswer — i.e. the label exists but has no IPv4)
            try:
                resolver = self._get_resolver()
                answers = await resolver.resolve(fqdn, "AAAA")
                if answers:
                    return fqdn
            except Exception:
                pass

            # Try CNAME (IPv6-only rare; CNAME-only common for SaaS aliases)
            try:
                resolver = self._get_resolver()
                answers = await resolver.resolve(fqdn, "CNAME")
                if answers:
                    return fqdn
            except Exception:
                pass

        return None

    def _load_wordlist(self) -> List[str]:
        """Load subdomain wordlist from file.

        If self.max_words is set, only the first N words are returned (wordlists are
        ordered by frequency/popularity, so top-N gives the best hit rate per second).
        """
        words = []
        path = Path(self.wordlist_path)
        if not path.exists():
            return words
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip().lower()
                if word and not word.startswith("#"):
                    words.append(word)
        max_words = getattr(self, "max_words", None)
        if max_words and len(words) > max_words:
            words = words[:max_words]
        return words

    async def brute_force(self) -> Set[str]:
        """Run DNS brute force against the wordlist (via the resolver backend)."""
        words = self._load_wordlist()
        if not words:
            return self.results
        await self.bulk_resolve(words)
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
        self.resolver_backend = None  # optional MassdnsResolver; None => dnspython
        self._resolvers: List[dns.asyncresolver.Resolver] = []
        self._setup_resolvers()

    async def bulk_resolve(self, prefixes) -> Set[str]:
        """Resolve permutation *prefixes* against ``self.domain`` — massdns backend
        when attached + usable, else per-name dnspython via ``_resolve_one``."""
        prefixes = [p for p in prefixes if p]
        if not prefixes:
            return set()
        backend = getattr(self, "resolver_backend", None)
        if backend is not None and getattr(backend, "binary", None):
            wc_ips = (self.wildcard.wildcard_ips
                      if getattr(self.wildcard, "has_wildcard", False) else set())
            fqdns = [f"{p}.{self.domain}" for p in prefixes]
            records = await backend.resolve(fqdns, wildcard_ips=wc_ips)
            hits = set(records.keys())
            for h in hits:
                self.results.add(h)
                if self.callback:
                    self.callback(h)
            return hits
        semaphore = asyncio.Semaphore(self.concurrency)
        tasks = [self._resolve_one(p, semaphore) for p in prefixes]
        hits: Set[str] = set()
        for i in range(0, len(tasks), 1000):
            batch = tasks[i:i + 1000]
            for r in await asyncio.gather(*batch, return_exceptions=True):
                if isinstance(r, str) and r:
                    hits.add(r)
                    self.results.add(r)
                    if self.callback:
                        self.callback(r)
        return hits

    def _setup_resolvers(self):
        dns_servers = [
            ["8.8.8.8", "8.8.4.4"],
            ["1.1.1.1", "1.0.0.1"],
            ["9.9.9.9", "149.112.112.112"],
        ]
        for servers in dns_servers:
            r = dns.asyncresolver.Resolver()
            r.nameservers = servers
            r.timeout = 1.5
            r.lifetime = 2.5
            self._resolvers.append(r)

    def _generate_permutations(self) -> Set[str]:
        """Generate permutations of discovered subdomains via the target-learned
        mutation engine ([2]): a frequency word cloud of the target's own naming
        tokens, recombined across every parent + a static affix seed set, deduped
        (optionally against a shared bloom for loop-until-dry). Signature preserved
        — the Falcon adapter and the phase loop call this unchanged."""
        return generate_mutations(
            self.found,
            self.domain,
            static_affixes=STATIC_AFFIXES,
            max_mutations=getattr(self, "max_mutations", DEFAULT_MAX_MUTATIONS),
            bloom=getattr(self, "_bloom", None),
        )

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
        await self.bulk_resolve(perms)
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
        # [3] optional shared massdns backend (attr-injected, like the other
        # scanners) + a per-parent wildcard cache so we detect each base's
        # wildcard once, not once per candidate.
        self.resolver_backend = None
        self._wc_cache: dict = {}

    def _prefix_depth(self, fqdn: str) -> int:
        """Number of labels between *fqdn* and the base domain (1 == direct sub)."""
        prefix = fqdn[: -len(self.domain) - 1] if fqdn.endswith("." + self.domain) else ""
        return len([p for p in prefix.split(".") if p]) if prefix else 0

    async def _wildcard_for(self, base: str) -> WildcardDetector:
        wc = self._wc_cache.get(base)
        if wc is None:
            wc = WildcardDetector(base)
            try:
                await wc.detect()
            except Exception:
                pass
            self._wc_cache[base] = wc
        return wc

    async def enumerate(self) -> Set[str]:
        """Recursively brute the wordlist under discovered subdomains, honoring
        ``max_depth`` (breadth-first: each newly-found deeper name becomes a base
        for the next level, up to max_depth). Uses the shared resolver backend
        when attached, else per-name dnspython."""
        words = self._load_small_wordlist()
        if not words:
            return self.results

        # Level-1 frontier: the directly-under-apex names we already know.
        frontier = {s for s in self.found if self._prefix_depth(s) == 1}
        depth = 1
        while frontier and depth <= self.max_depth:
            next_frontier: Set[str] = set()
            for base in sorted(frontier):
                wc = await self._wildcard_for(base)
                hits = await self._resolve_words_under(base, words, wc)
                for h in hits:
                    if h not in self.results:
                        self.results.add(h)
                        if self.callback:
                            self.callback(h)
                        next_frontier.add(h)
            frontier = next_frontier
            depth += 1
        return self.results

    async def _resolve_words_under(self, base: str, words: List[str],
                                   wc: WildcardDetector) -> Set[str]:
        """Resolve ``<word>.<base>`` for every word — massdns backend in one bulk
        pass when attached, else per-name dnspython."""
        backend = getattr(self, "resolver_backend", None)
        fqdns = [f"{w}.{base}" for w in words]
        if backend is not None and getattr(backend, "binary", None):
            wc_ips = wc.wildcard_ips if getattr(wc, "has_wildcard", False) else set()
            records = await backend.resolve(fqdns, wildcard_ips=wc_ips)
            return set(records.keys())
        semaphore = asyncio.Semaphore(self.concurrency)
        tasks = [self._resolve(fqdn, wc, semaphore) for fqdn in fqdns]
        hits: Set[str] = set()
        for r in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(r, str) and r:
                hits.add(r)
        return hits

    def _load_small_wordlist(self) -> List[str]:
        """Load a subset of the wordlist for recursive enumeration. Size is
        configurable via the ``max_recursive_words`` attr (default 500)."""
        path = Path(self.wordlist_path)
        if not path.exists():
            return []
        limit = getattr(self, "max_recursive_words", 500)
        words = []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip().lower()
                if word and not word.startswith("#"):
                    words.append(word)
                if len(words) >= limit:
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
