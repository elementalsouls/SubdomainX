"""`run()` gates Phase 6 (DNS resolution + optional HTTP probe) on `resolve_names`,
decoupled from `probe`.

Why: an embedder (Falcon-Recon) runs its OWN richer HTTP probe (httpx), so it sets
`probe=False` to stop SubdomainX duplicating HTTP work. But the OLD `run()` gated the
WHOLE `_resolve_phase` on `probe`, so with `probe=False` SubdomainX never DNS-resolved
its discovered names — passive-discovered non-HTTP hosts (crm/autodiscover/ntp/…) got
NO IP, and the embedder's graph never learned them. `_resolve_phase` already gates its
HTTP work separately (`SubdomainResolver(check_http=self.config.probe)`), so running it
with `probe=False` is a pure DNS pass. `resolve_names` (default: follow `probe` for
standalone use) lets the embedder turn resolution on without turning HTTP probing on.
"""
from __future__ import annotations

import argparse
import asyncio

from subdomainx.__main__ import SubdomainX


def _sx(**cfg):
    # Config attrs run()'s banner + phase gates read (Falcon's _build_sx_config
    # sets all of these; the test supplies the minimal set).
    base = dict(concurrency=10, no_bruteforce=True, permutations=False,
                recursive=False, probe=True, output=None)
    base.update(cfg)
    ns = argparse.Namespace(domain="example.com", **base)
    sx = SubdomainX(ns)
    called = {"resolve": False}

    async def _noop():
        return None

    async def _resolve():
        called["resolve"] = True

    # Stub every phase so run() does no network; track _resolve_phase.
    sx._passive_phase = _noop
    sx._zone_transfer_phase = _noop
    sx._bruteforce_phase = _noop
    sx._permutation_phase = _noop
    sx._recursive_phase = _noop
    sx._convergence_phase = _noop
    sx._resolve_phase = _resolve
    sx._print_results = lambda: None
    sx._save_results = lambda: None
    return sx, called


def test_resolve_runs_when_resolve_names_set_even_if_probe_false():
    # The Falcon + web_probe case: probe off, but resolution explicitly requested.
    sx, called = _sx(probe=False, resolve_names=True, no_bruteforce=True,
                     permutations=False, recursive=False, output=None)
    asyncio.run(sx.run())
    assert called["resolve"] is True


def test_resolve_skipped_when_resolve_names_false():
    sx, called = _sx(probe=False, resolve_names=False, no_bruteforce=True,
                     permutations=False, recursive=False, output=None)
    asyncio.run(sx.run())
    assert called["resolve"] is False


def test_resolve_names_defaults_to_probe_when_absent():
    # Backward-compatible standalone behaviour: no resolve_names attr → follow probe.
    sx, called = _sx(probe=True, no_bruteforce=True, permutations=False,
                     recursive=False, output=None)
    asyncio.run(sx.run())
    assert called["resolve"] is True
