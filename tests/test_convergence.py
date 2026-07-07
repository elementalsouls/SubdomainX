"""[3] Loop-until-dry convergence + RecursiveEnumerator max_depth.

All offline: a FakeBackend stands in for massdns (truthy `binary`, resolves a
preset "live" set and records every fqdn it was asked for), so no DNS traffic.
"""
from __future__ import annotations

import argparse
import asyncio

import pytest

from subdomainx.__main__ import SubdomainX
from subdomainx.active import RecursiveEnumerator, WildcardDetector


class FakeBackend:
    def __init__(self, live):
        self.binary = "/usr/bin/massdns"
        self.live = set(live)
        self.requested = []  # every fqdn asked, across all calls

    async def resolve(self, fqdns, wildcard_ips=None):
        out = {}
        for f in fqdns:
            name = f.rstrip(".")
            self.requested.append(name)
            if name in self.live:
                out[name] = {"ips": ["1.2.3.4"], "ipv6s": [], "cnames": []}
        return out


def _sx(domain="example.com", **cfg):
    cfg.setdefault("concurrency", 10)
    ns = argparse.Namespace(domain=domain, **cfg)
    sx = SubdomainX(ns)
    sx._shared_wildcard = WildcardDetector(domain)  # no-wildcard, avoids network detect
    return sx


# ── convergence loop control ─────────────────────────────────────────────────

def test_convergence_stops_after_n_empty_rounds(monkeypatch):
    sx = _sx(mutation_rounds=3)
    scripted = [2, 1, 0, 0, 0, 9, 9]  # should stop at the 3rd consecutive 0 (round 5)
    calls = {"n": 0}

    async def fake_round(self, wc, bloom):
        i = calls["n"]
        calls["n"] += 1
        return scripted[i]
    monkeypatch.setattr(SubdomainX, "_mutation_round", fake_round)

    asyncio.run(sx._convergence_phase())
    assert calls["n"] == 5  # 2,1,0,0,0 -> three consecutive empties ends it


def test_convergence_disabled_when_rounds_zero(monkeypatch):
    sx = _sx(mutation_rounds=0)
    called = {"n": 0}

    async def fake_round(self, wc, bloom):
        called["n"] += 1
        return 0
    monkeypatch.setattr(SubdomainX, "_mutation_round", fake_round)
    asyncio.run(sx._convergence_phase())
    assert called["n"] == 0


# ── offline convergence fixture: converges + never re-emits known names ───────

def test_convergence_finds_new_then_dries_without_reemitting_known():
    sx = _sx(mutation_rounds=3)
    sx._massdns = FakeBackend(live={"dev-api.example.com"})
    sx.all_subdomains = {"api.example.com"}

    asyncio.run(sx._convergence_phase())

    # Round 1 mutates "api" -> "dev-api" (static affix), which resolves.
    assert "dev-api.example.com" in sx.all_subdomains
    # The known parent prefix "api" must never be re-queried as a candidate.
    assert "api.example.com" not in sx._massdns.requested
    # The shared bloom means each discovered name is attempted at most once across
    # all rounds — no infinite re-emission (test completing at all proves it halts).
    assert sx._massdns.requested.count("dev-api.example.com") == 1


# ── RecursiveEnumerator honors max_depth ─────────────────────────────────────

def _recursor(found, max_depth, live, monkeypatch):
    r = RecursiveEnumerator("example.com", set(found), "/nonexistent",
                            WildcardDetector("example.com"), max_depth=max_depth)
    r.resolver_backend = FakeBackend(live=live)
    monkeypatch.setattr(RecursiveEnumerator, "_load_small_wordlist", lambda self: ["x", "y"])
    # Stub per-parent wildcard detection so no real DNS is issued.
    async def _no_detect(self):
        return False, set()
    monkeypatch.setattr(WildcardDetector, "detect", _no_detect)
    return r


def test_recursive_depth_1_does_not_reach_level_3(monkeypatch):
    # y.x.a.example.com is only reachable by recursing INTO x.a (a level-2 name).
    r = _recursor(found={"a.example.com"}, max_depth=1,
                  live={"x.a.example.com", "y.x.a.example.com"}, monkeypatch=monkeypatch)
    results = asyncio.run(r.enumerate())
    assert "x.a.example.com" in results
    assert "y.x.a.example.com" not in results  # gated by max_depth=1


def test_recursive_depth_2_reaches_deeper_level(monkeypatch):
    r = _recursor(found={"a.example.com"}, max_depth=2,
                  live={"x.a.example.com", "y.x.a.example.com"}, monkeypatch=monkeypatch)
    results = asyncio.run(r.enumerate())
    assert "x.a.example.com" in results
    assert "y.x.a.example.com" in results  # depth 2 recurses into x.a


def test_recursive_uses_backend_bulk(monkeypatch):
    r = _recursor(found={"a.example.com"}, max_depth=1,
                  live={"x.a.example.com"}, monkeypatch=monkeypatch)
    asyncio.run(r.enumerate())
    # backend was asked for the words under the base (bulk), not skipped
    assert "x.a.example.com" in r.resolver_backend.requested
