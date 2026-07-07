"""LIVE regression test for numbered-sequence enumeration (commit 4dd30e6).

End-to-end proof that the mutation engine, given ONE member of a numbered
sequence, discovers a LIVE sibling it could not have generated before the
`_number_stem` fix (old engine: ntsmtp1 -> ntsmtp11, never ntsmtp2).

OPT-IN + network: hits real DNS, so it is gated behind ``SUBDOMAINX_LIVE=1`` and
the ``live`` marker — the default offline suite never runs it.

SELF-HEALING: the whole proof rests on an external anchor (yamaha-motor.com's
ntsmtp1/ntsmtp2, a clean non-wildcard sequence at the time of writing). If that
world changes — the seed goes dark, the sibling is decommissioned, or the zone
sprouts a wildcard — the test SKIPS (not fails), because a dead anchor invalidates
the premise rather than the code. So it can only fail if the *engine* regresses.
"""
from __future__ import annotations

import asyncio
import os
import sys

import pytest

pytestmark = pytest.mark.live

_LIVE = os.environ.get("SUBDOMAINX_LIVE") == "1"

# Anchor: a clean, non-wildcard numbered sequence with live members.
DOMAIN = "yamaha-motor.com"
SEED = "ntsmtp1"          # the single member we feed the engine
SIBLING = "ntsmtp2"       # the live sibling the engine must re-derive + resolve


def _win_selector():
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


async def _resolves(fqdn: str) -> bool:
    import dns.asyncresolver as ar
    r = ar.Resolver()
    r.nameservers = ["1.1.1.1", "8.8.8.8"]
    r.timeout = 5
    r.lifetime = 8
    for rt in ("A", "AAAA", "CNAME"):
        try:
            if await r.resolve(fqdn, rt):
                return True
        except Exception:
            continue
    return False


@pytest.mark.skipif(not _LIVE, reason="set SUBDOMAINX_LIVE=1 to run live DNS tests")
def test_single_seed_recovers_live_numbered_sibling():
    _win_selector()
    from subdomainx.active import PermutationScanner, WildcardDetector

    async def run():
        wc = WildcardDetector(DOMAIN)
        await wc.detect()
        # Premise guards — skip (don't fail) if the external world moved.
        if wc.has_wildcard:
            pytest.skip(f"{DOMAIN} now serves a wildcard — anchor invalidated")
        if not await _resolves(f"{SEED}.{DOMAIN}"):
            pytest.skip(f"anchor seed {SEED}.{DOMAIN} no longer resolves")
        if not await _resolves(f"{SIBLING}.{DOMAIN}"):
            pytest.skip(f"anchor sibling {SIBLING}.{DOMAIN} decommissioned — premise gone")

        scanner = PermutationScanner(DOMAIN, {f"{SEED}.{DOMAIN}"}, wc, concurrency=60)
        scanner.resolver_validation = True  # real-scan conditions ([5] trust tier)

        # (a) the engine must GENERATE the sibling from the single seed …
        perms = scanner._generate_permutations()
        assert SIBLING in perms, (
            f"sequence-enum regressed: seed {SEED} did not generate {SIBLING} "
            f"(numbered-sequence enumeration broken)")

        # (b) … and end-to-end resolve+validate it as a live host.
        hits = await scanner.scan()
        assert f"{SIBLING}.{DOMAIN}" in hits, (
            f"engine generated {SIBLING} but did not resolve+accept it live; "
            f"got {sorted(hits)}")

    asyncio.run(run())
