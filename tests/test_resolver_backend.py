"""[1] massdns/shuffledns resolver backend — selection + output parsing.

The backend is OPTIONAL: massdns is a Linux-native bulk resolver. When the binary
is absent (e.g. Windows, or not installed) selection MUST fall back to dnspython so
SubdomainX still runs with zero external binaries. These tests cover the pure logic
(binary detection, backend selection, massdns -oJ parsing) without needing massdns.
"""
from __future__ import annotations

from subdomainx.resolver_massdns import (
    MassdnsResolver,
    select_backend,
    parse_massdns_ndjson,
)


# ── backend selection ────────────────────────────────────────────────────────

def test_auto_falls_back_to_dnspython_when_binary_absent():
    assert select_backend("auto", binary=None) == "dnspython"


def test_auto_uses_massdns_when_binary_present():
    assert select_backend("auto", binary="/usr/bin/massdns") == "massdns"


def test_explicit_massdns_without_binary_falls_back_not_crash():
    # Asking for massdns but it's not installed must degrade, never hard-fail.
    assert select_backend("massdns", binary=None) == "dnspython"


def test_explicit_dnspython_never_uses_massdns_even_if_present():
    assert select_backend("dnspython", binary="/usr/bin/massdns") == "dnspython"


def test_unknown_preference_defaults_to_dnspython():
    assert select_backend("banana", binary="/usr/bin/massdns") == "dnspython"


# ── massdns -oJ (ndjson) parsing ─────────────────────────────────────────────

_SAMPLE = "\n".join([
    # a resolving A record
    '{"name":"api.example.com.","type":"A","class":"IN","status":"NOERROR",'
    '"data":{"answers":[{"name":"api.example.com.","type":"A","class":"IN","data":"1.2.3.4"}]}}',
    # a CNAME + AAAA
    '{"name":"cdn.example.com.","type":"A","class":"IN","status":"NOERROR",'
    '"data":{"answers":['
    '{"name":"cdn.example.com.","type":"CNAME","class":"IN","data":"edge.fastly.net."},'
    '{"name":"cdn.example.com.","type":"AAAA","class":"IN","data":"2606:2800::1"}]}}',
    # NXDOMAIN — must NOT appear as resolved
    '{"name":"nope.example.com.","type":"A","class":"IN","status":"NXDOMAIN","data":{"answers":[]}}',
    "",  # blank line tolerated
    "garbage-not-json",  # junk tolerated
])


def test_parse_extracts_only_resolving_names():
    out = parse_massdns_ndjson(_SAMPLE)
    assert set(out) == {"api.example.com", "cdn.example.com"}  # nxdomain dropped, trailing dot stripped


def test_parse_captures_a_records():
    out = parse_massdns_ndjson(_SAMPLE)
    assert out["api.example.com"]["ips"] == ["1.2.3.4"]


def test_parse_captures_cname_and_aaaa():
    out = parse_massdns_ndjson(_SAMPLE)
    assert out["cdn.example.com"]["cnames"] == ["edge.fastly.net"]
    assert out["cdn.example.com"]["ipv6s"] == ["2606:2800::1"]


def test_parse_tolerates_blank_and_garbage_lines():
    # already includes blank + junk in _SAMPLE; must not raise and must skip them
    out = parse_massdns_ndjson(_SAMPLE)
    assert "nope.example.com" not in out


def test_parse_empty_input_is_empty_dict():
    assert parse_massdns_ndjson("") == {}
    assert parse_massdns_ndjson(None) == {}


# ── detect (binary autodetection) ────────────────────────────────────────────

def test_detect_returns_none_when_no_binary(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert MassdnsResolver.detect() is None


def test_detect_prefers_massdns_over_shuffledns(monkeypatch):
    monkeypatch.setattr("shutil.which",
                        lambda name: "/usr/bin/" + name if name in ("massdns", "shuffledns") else None)
    # massdns is the direct bulk resolver; prefer it
    assert MassdnsResolver.detect() == "/usr/bin/massdns"


def test_detect_honors_explicit_env_path(monkeypatch, tmp_path):
    fake = tmp_path / "massdns"
    fake.write_text("")
    monkeypatch.setenv("SUBDOMAINX_MASSDNS", str(fake))
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert MassdnsResolver.detect() == str(fake)


def test_is_available_reflects_detect(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    monkeypatch.delenv("SUBDOMAINX_MASSDNS", raising=False)
    assert MassdnsResolver.is_available() is False
