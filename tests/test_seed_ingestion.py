"""[0] External seed ingestion — SubdomainX.add_seed_subdomains().

Falcon runs CT/passive-DNS/dns_deep in stage 1 (before the subdomain module), so
those names are already in ctx.graph when SubdomainX starts. Instead of SubdomainX
re-querying passive sources, the adapter feeds those names in as seeds: they
pre-populate all_subdomains AND the mutation corpus so the mutation engine learns
from them, without any extra network calls. Seedless/keyless-safe: empty in == today.
"""
from __future__ import annotations

import argparse

from subdomainx.__main__ import SubdomainX


def _sx(domain="example.com"):
    return SubdomainX(argparse.Namespace(domain=domain))


def test_seeds_pre_populate_all_subdomains():
    sx = _sx()
    n = sx.add_seed_subdomains({"api.example.com", "vpn.example.com"})
    assert n == 2
    assert "api.example.com" in sx.all_subdomains
    assert "vpn.example.com" in sx.all_subdomains


def test_seeds_feed_the_mutation_corpus():
    sx = _sx()
    sx.add_seed_subdomains({"api.example.com"})
    # dedicated seed set the mutation engine ([2]) learns from
    assert "api.example.com" in sx.seed_subdomains


def test_seeds_are_normalized_lowercased_and_dot_stripped():
    sx = _sx()
    sx.add_seed_subdomains({"API.Example.com.", "  vpn.example.com "})
    assert "api.example.com" in sx.all_subdomains
    assert "vpn.example.com" in sx.all_subdomains
    # no trailing dot / whitespace / uppercase leaked in
    assert all(s == s.strip().lower().rstrip(".") for s in sx.all_subdomains)


def test_out_of_scope_names_are_rejected():
    sx = _sx("example.com")
    n = sx.add_seed_subdomains({
        "api.example.com",          # in scope
        "evil.attacker.com",        # out of scope — different apex
        "example.com.evil.com",     # out of scope — suffix trick
    })
    assert n == 1
    assert "api.example.com" in sx.all_subdomains
    assert "evil.attacker.com" not in sx.all_subdomains
    assert "example.com.evil.com" not in sx.all_subdomains


def test_apex_itself_is_accepted():
    sx = _sx("example.com")
    sx.add_seed_subdomains({"example.com"})
    assert "example.com" in sx.all_subdomains


def test_empty_or_none_is_a_noop():
    sx = _sx()
    assert sx.add_seed_subdomains(set()) == 0
    assert sx.add_seed_subdomains(None) == 0
    assert sx.all_subdomains == set()


def test_seed_count_recorded_in_source_counts():
    sx = _sx()
    sx.add_seed_subdomains({"api.example.com", "vpn.example.com"})
    assert sx.source_counts.get("seed") == 2


def test_seeding_is_idempotent_on_all_subdomains():
    sx = _sx()
    sx.add_seed_subdomains({"api.example.com"})
    added = sx.add_seed_subdomains({"api.example.com", "new.example.com"})
    # only the genuinely-new name counts as added
    assert added == 1
    assert sx.all_subdomains == {"api.example.com", "new.example.com"}
