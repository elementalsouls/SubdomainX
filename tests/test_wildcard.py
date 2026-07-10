"""[4] Robust wildcard detection — per-parent cache, CNAME-wildcard aware, junk
filter. Offline: _probe is stubbed so no DNS is issued."""
from __future__ import annotations

import asyncio

import pytest

from subdomainx.active import WildcardDetector


def _stub_probe(wd, ip_sets, cname_sets, counter=None):
    async def _p(parent):
        if counter is not None:
            counter["n"] += 1
        return list(ip_sets), list(cname_sets)
    wd._probe = _p


# ── resolver must not depend on (possibly unreachable) system DNS ─────────────

def test_wildcard_resolver_uses_explicit_public_nameservers():
    """The wildcard probe must use explicit public resolvers, NOT the system
    config. Some corporate/ISP resolvers do not answer direct dnspython UDP, so a
    system-configured resolver times out on every probe — which made wildcard
    detection stall and starved active subdomain resolution (Falcon jakson.com
    run: 66 subdomains, 0 resolved). The bruteforce pool already sets explicit
    nameservers; the wildcard detector must too."""
    wd = WildcardDetector("example.com")
    ns = wd._resolver.nameservers
    assert ns, "wildcard resolver has no explicit nameservers (would use system DNS)"
    assert all(not str(n).startswith(("127.", "0.")) for n in ns)
    assert any(str(n) in ("1.1.1.1", "8.8.8.8", "9.9.9.9") for n in ns)


# ── per-parent cache ─────────────────────────────────────────────────────────

def test_detect_parent_caches_and_probes_once():
    wd = WildcardDetector("example.com")
    counter = {"n": 0}
    _stub_probe(wd, [{"1.2.3.4"}] * 5, [set()] * 5, counter)
    a = asyncio.run(wd.detect_parent("a.example.com"))
    b = asyncio.run(wd.detect_parent("a.example.com"))
    assert a == b
    assert counter["n"] == 1  # second call served from cache


def test_distinct_parents_probed_separately():
    wd = WildcardDetector("example.com")
    counter = {"n": 0}
    _stub_probe(wd, [{"1.2.3.4"}] * 5, [set()] * 5, counter)
    asyncio.run(wd.detect_parent("a.example.com"))
    asyncio.run(wd.detect_parent("b.example.com"))
    assert counter["n"] == 2


# ── IP wildcard (back-compat) ────────────────────────────────────────────────

def test_ip_wildcard_detected_and_matched():
    wd = WildcardDetector("example.com")
    _stub_probe(wd, [{"9.9.9.9"}] * 5, [set()] * 5)
    has, ips = asyncio.run(wd.detect())
    assert has and ips == {"9.9.9.9"}
    assert wd.is_wildcard({"9.9.9.9"}) is True
    assert wd.is_wildcard({"1.1.1.1"}) is False


def test_no_wildcard_when_answers_differ():
    wd = WildcardDetector("example.com")
    _stub_probe(wd, [{"1.1.1.1"}, {"2.2.2.2"}, {"3.3.3.3"}, set(), set()], [set()] * 5)
    has, ips = asyncio.run(wd.detect())
    assert has is False and ips == set()
    assert wd.is_wildcard({"1.1.1.1"}) is False


# ── CNAME wildcard ───────────────────────────────────────────────────────────

def test_cname_wildcard_detected():
    wd = WildcardDetector("example.com")
    _stub_probe(wd, [set()] * 5, [{"wild.cdn.net"}] * 5)
    has, ips = asyncio.run(wd.detect())
    assert has is True
    assert wd.wildcard_cnames == {"wild.cdn.net"}
    # matched by CNAME even though there is no wildcard IP
    assert wd.is_wildcard(set(), cnames={"wild.cdn.net"}) is True
    assert wd.is_wildcard(set(), cnames={"real.target.net"}) is False


# ── junk / PTR-like filter ───────────────────────────────────────────────────

def test_is_junk_drops_ptr_like_names():
    assert WildcardDetector.is_junk("10-20-30-40.example.com")
    assert WildcardDetector.is_junk("192.example.com")
    assert WildcardDetector.is_junk("")


def test_is_junk_keeps_real_names():
    assert not WildcardDetector.is_junk("api.example.com")
    assert not WildcardDetector.is_junk("vpn-gw.example.com")
    assert not WildcardDetector.is_junk("s3.example.com")
