"""[1] bulk_resolve routing — DNSBruteForcer / PermutationScanner use the massdns
backend when one is attached, else fall back to per-name dnspython (_resolve_one).
Offline: the backend + _resolve_one are faked so no DNS traffic occurs.
"""
from __future__ import annotations

import asyncio

import pytest

from subdomainx.active import DNSBruteForcer, PermutationScanner, WildcardDetector


class _FakeBackend:
    """Stand-in for MassdnsResolver: has a truthy `binary` and returns records."""
    def __init__(self, resolves):
        self.binary = "/usr/bin/massdns"
        self._resolves = resolves  # set of fqdns that "resolve"
        self.calls = 0

    async def resolve(self, fqdns, wildcard_ips=None):
        self.calls += 1
        return {f.rstrip("."): {"ips": ["1.2.3.4"], "ipv6s": [], "cnames": []}
                for f in fqdns if f.rstrip(".") in self._resolves}


def _bruter(domain="example.com"):
    wc = WildcardDetector(domain)
    return DNSBruteForcer(domain, wordlist_path="/nonexistent", wildcard_detector=wc)


def test_bruteforce_uses_backend_when_attached():
    b = _bruter()
    b.resolver_backend = _FakeBackend({"api.example.com", "vpn.example.com"})
    hits = asyncio.run(b.bulk_resolve(["api", "vpn", "nope"]))
    assert hits == {"api.example.com", "vpn.example.com"}
    assert b.results == hits
    assert b.resolver_backend.calls == 1  # single bulk pass, not per-name


def test_bruteforce_falls_back_to_dnspython_when_no_backend(monkeypatch):
    b = _bruter()
    assert b.resolver_backend is None

    async def fake_resolve_one(self, word, sem):
        return f"{word}.example.com" if word == "api" else None
    monkeypatch.setattr(DNSBruteForcer, "_resolve_one", fake_resolve_one)

    hits = asyncio.run(b.bulk_resolve(["api", "nope"]))
    assert hits == {"api.example.com"}


def test_backend_with_no_binary_is_ignored(monkeypatch):
    # A backend object whose binary is None must NOT be used — fall back.
    b = _bruter()
    class _Empty:
        binary = None
    b.resolver_backend = _Empty()

    async def fake_resolve_one(self, word, sem):
        return f"{word}.example.com" if word == "api" else None
    monkeypatch.setattr(DNSBruteForcer, "_resolve_one", fake_resolve_one)

    hits = asyncio.run(b.bulk_resolve(["api", "x"]))
    assert hits == {"api.example.com"}


def test_permutation_scanner_uses_backend():
    wc = WildcardDetector("example.com")
    s = PermutationScanner("example.com", {"api.example.com"}, wc)
    s.resolver_backend = _FakeBackend({"dev-api.example.com"})
    hits = asyncio.run(s.bulk_resolve(["dev-api", "qa-api"]))
    assert hits == {"dev-api.example.com"}
    assert s.resolver_backend.calls == 1


def test_empty_input_short_circuits():
    b = _bruter()
    b.resolver_backend = _FakeBackend(set())
    assert asyncio.run(b.bulk_resolve([])) == set()
    assert b.resolver_backend.calls == 0
