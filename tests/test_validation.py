"""[5] Resolver trust tier — re-verify fast-path hits on trusted resolvers.

Offline: TrustedVerifier._resolves is stubbed and a FakeVerifier stands in, so no
DNS is issued. Proves poisoned/stale hits are dropped before acceptance.
"""
from __future__ import annotations

import asyncio

import pytest

from subdomainx.validation import TrustedVerifier, maybe_verify
from subdomainx.active import DNSBruteForcer, PermutationScanner, WildcardDetector


class FakeVerifier:
    def __init__(self, keep):
        self.keep = set(keep)
        self.seen = set()

    async def verify(self, fqdns):
        fqdns = set(fqdns)
        self.seen |= fqdns
        return fqdns & self.keep


class FakeBackend:
    def __init__(self, live):
        self.binary = "/usr/bin/massdns"
        self.live = set(live)

    async def resolve(self, fqdns, wildcard_ips=None):
        return {f.rstrip("."): {"ips": ["1.2.3.4"], "ipv6s": [], "cnames": []}
                for f in fqdns if f.rstrip(".") in self.live}


# ── TrustedVerifier ──────────────────────────────────────────────────────────

def test_trusted_verifier_keeps_only_resolving(monkeypatch):
    tv = TrustedVerifier()
    live = {"api.example.com"}

    async def _resolves(self, fqdn):
        return fqdn in live
    monkeypatch.setattr(TrustedVerifier, "_resolves", _resolves)

    out = asyncio.run(tv.verify(["api.example.com", "ghost.example.com"]))
    assert out == {"api.example.com"}


def test_trusted_verifier_empty_input():
    assert asyncio.run(TrustedVerifier().verify([])) == set()


# ── maybe_verify gating ──────────────────────────────────────────────────────

def test_maybe_verify_passthrough_when_disabled():
    class Obj:
        resolver_validation = False
    out = asyncio.run(maybe_verify(Obj(), {"a.example.com", "b.example.com"}))
    assert out == {"a.example.com", "b.example.com"}  # unchanged


def test_maybe_verify_filters_when_enabled():
    class Obj:
        resolver_validation = True
        _verifier = FakeVerifier(keep={"a.example.com"})
    out = asyncio.run(maybe_verify(Obj(), {"a.example.com", "b.example.com"}))
    assert out == {"a.example.com"}


# ── integration: bulk_resolve drops unverified massdns hits ──────────────────

def test_bruteforce_massdns_hits_are_reverified():
    b = DNSBruteForcer("example.com", "/nonexistent", WildcardDetector("example.com"))
    b.resolver_backend = FakeBackend(live={"api.example.com", "poisoned.example.com"})
    b.resolver_validation = True
    b._verifier = FakeVerifier(keep={"api.example.com"})   # trusted set rejects the poisoned one
    hits = asyncio.run(b.bulk_resolve(["api", "poisoned"]))
    assert hits == {"api.example.com"}
    assert b.results == {"api.example.com"}


def test_validation_off_keeps_all_massdns_hits():
    b = DNSBruteForcer("example.com", "/nonexistent", WildcardDetector("example.com"))
    b.resolver_backend = FakeBackend(live={"api.example.com", "x.example.com"})
    b.resolver_validation = False   # default at this layer
    hits = asyncio.run(b.bulk_resolve(["api", "x"]))
    assert hits == {"api.example.com", "x.example.com"}


def test_permutation_massdns_hits_are_reverified():
    s = PermutationScanner("example.com", {"api.example.com"}, WildcardDetector("example.com"))
    s.resolver_backend = FakeBackend(live={"dev-api.example.com", "bad.example.com"})
    s.resolver_validation = True
    s._verifier = FakeVerifier(keep={"dev-api.example.com"})
    hits = asyncio.run(s.bulk_resolve(["dev-api", "bad"]))
    assert hits == {"dev-api.example.com"}
