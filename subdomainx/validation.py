"""[5] Resolver trust tier.

Candidates are resolved on the fast public / massdns path for speed; every HIT is
then RE-VERIFIED on a small curated trusted-resolver set before it is accepted.
This guards against DNS cache poisoning / stale public-resolver answers — important
because Falcon files findings on these names, so a false positive is expensive.

Opt-in at the object level (``resolver_validation`` attr defaults off, so low-level
unit tests of bulk_resolve don't hit the network); the CLI/adapter turn it ON by
default and attach a shared verifier to the scanners.
"""
from __future__ import annotations

import asyncio
import random
from typing import Iterable, List, Optional, Set

import dns.asyncresolver

# Curated, high-integrity resolvers for re-verification (Cloudflare / Google / Quad9).
TRUSTED_RESOLVERS: List[List[str]] = [
    ["1.1.1.1", "1.0.0.1"],
    ["8.8.8.8", "8.8.4.4"],
    ["9.9.9.9", "149.112.112.112"],
]


class TrustedVerifier:
    """Re-resolve names on a small trusted resolver set; keep only those that still
    resolve (A / AAAA / CNAME)."""

    def __init__(self, resolvers: Optional[List[List[str]]] = None,
                 concurrency: int = 50, timeout: float = 3.0):
        self.concurrency = concurrency
        self._resolvers: List[dns.asyncresolver.Resolver] = []
        for servers in (resolvers or TRUSTED_RESOLVERS):
            r = dns.asyncresolver.Resolver()
            r.nameservers = list(servers)
            r.timeout = timeout
            r.lifetime = timeout * 1.5
            self._resolvers.append(r)

    async def _resolves(self, fqdn: str) -> bool:
        """True if *fqdn* resolves on a trusted resolver (A, then AAAA, then CNAME)."""
        resolver = random.choice(self._resolvers) if self._resolvers else None
        if resolver is None:
            return False
        for rtype in ("A", "AAAA", "CNAME"):
            try:
                answers = await resolver.resolve(fqdn, rtype)
                if answers:
                    return True
            except (dns.asyncresolver.NXDOMAIN, dns.asyncresolver.NoNameservers):
                return False
            except dns.asyncresolver.NoAnswer:
                continue
            except Exception:
                # timeout / transient — try the next record type, else unconfirmed
                continue
        return False

    async def verify(self, fqdns: Iterable[str]) -> Set[str]:
        names = [f for f in fqdns if f]
        if not names:
            return set()
        semaphore = asyncio.Semaphore(self.concurrency)

        async def _one(fqdn: str):
            async with semaphore:
                return fqdn if await self._resolves(fqdn) else None

        results = await asyncio.gather(*[_one(f) for f in names], return_exceptions=True)
        return {r for r in results if isinstance(r, str) and r}


async def maybe_verify(obj, names: Iterable[str]) -> Set[str]:
    """Re-verify *names* through a trusted verifier IF ``obj.resolver_validation`` is
    on; otherwise return them unchanged. The verifier is created once and cached on
    ``obj._verifier``. Attr defaults OFF so low-level callers opt in explicitly."""
    names = set(names)
    if not names:
        return set()
    if not getattr(obj, "resolver_validation", False):
        return names
    verifier = getattr(obj, "_verifier", None)
    if verifier is None:
        verifier = TrustedVerifier()
        try:
            obj._verifier = verifier
        except Exception:
            pass
    return await verifier.verify(names)
