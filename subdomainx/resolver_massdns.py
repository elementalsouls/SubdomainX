"""[1] Optional massdns/shuffledns-backed bulk resolver.

massdns resolves hundreds of thousands of names per minute by pipelining UDP
queries across a large resolver pool — far faster than per-name dnspython. It is
Linux-native and OPTIONAL: when the binary is absent (Windows, or simply not
installed) `select_backend` falls back to ``"dnspython"`` so SubdomainX still runs
with zero external binaries.

This module is import-safe with no hard third-party deps (stdlib only). The pure
functions — `detect`, `select_backend`, `parse_massdns_ndjson` — carry the logic
and are unit-tested without the binary; `MassdnsResolver.resolve` shells out and
is exercised only where massdns actually exists.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set


# A small, reliable public-resolver pool for the bulk path. massdns needs a
# resolvers file; these are the same anycast resolvers the dnspython path uses.
_DEFAULT_RESOLVERS: List[str] = [
    "8.8.8.8", "8.8.4.4",
    "1.1.1.1", "1.0.0.1",
    "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220",
]


def select_backend(preference: Optional[str], binary: Optional[str] = None) -> str:
    """Resolve the effective backend name from a preference + binary availability.

    - "dnspython"     → always dnspython (never shell out).
    - "massdns"       → massdns IF the binary is present, else dnspython (degrade,
                        never hard-fail).
    - "auto" (default)→ massdns if present, else dnspython.
    - anything else   → dnspython.
    """
    pref = (preference or "auto").strip().lower()
    if pref == "dnspython":
        return "dnspython"
    if pref in ("massdns", "auto"):
        return "massdns" if binary else "dnspython"
    return "dnspython"


def parse_massdns_ndjson(text: Optional[str]) -> Dict[str, Dict[str, List[str]]]:
    """Parse massdns ``-o J`` (newline-delimited JSON) output.

    Returns ``{name: {"ips": [...], "ipv6s": [...], "cnames": [...]}}`` for every
    name that actually resolved (has at least one A/AAAA/CNAME answer and a non-
    error status). Trailing dots are stripped; blank/garbage lines are skipped.
    """
    out: Dict[str, Dict[str, List[str]]] = {}
    if not text:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        status = rec.get("status")
        if status and status != "NOERROR":
            continue
        name = (rec.get("name") or "").rstrip(".").lower()
        if not name:
            continue
        answers = ((rec.get("data") or {}).get("answers")) or []
        ips: List[str] = []
        ipv6s: List[str] = []
        cnames: List[str] = []
        for ans in answers:
            atype = ans.get("type")
            data = ans.get("data")
            if not data:
                continue
            if atype == "A":
                ips.append(str(data))
            elif atype == "AAAA":
                ipv6s.append(str(data))
            elif atype == "CNAME":
                cnames.append(str(data).rstrip("."))
        if ips or ipv6s or cnames:
            out[name] = {"ips": ips, "ipv6s": ipv6s, "cnames": cnames}
    return out


class MassdnsResolver:
    """Bulk DNS resolution via the massdns (or shuffledns) binary.

    Construct with an explicit binary path or let `detect` find one. `resolve`
    returns the same ``{name: {ips, ipv6s, cnames}}`` shape as
    `parse_massdns_ndjson`, filtered to genuinely-resolving names.
    """

    def __init__(self, binary: Optional[str] = None,
                 resolvers: Optional[List[str]] = None):
        self.binary = binary or self.detect()
        self.resolvers = resolvers or _DEFAULT_RESOLVERS

    # ── detection ────────────────────────────────────────────────────────────
    @staticmethod
    def detect() -> Optional[str]:
        """Return a usable massdns/shuffledns binary path, or None.

        Precedence: explicit ``SUBDOMAINX_MASSDNS`` env path → massdns on PATH →
        shuffledns on PATH (which itself wraps massdns)."""
        env = os.environ.get("SUBDOMAINX_MASSDNS")
        if env and Path(env).exists():
            return env
        for name in ("massdns", "shuffledns"):
            found = shutil.which(name)
            if found:
                return found
        return None

    @classmethod
    def is_available(cls) -> bool:
        return cls.detect() is not None

    def _subprocess_supported(self) -> bool:
        """asyncio subprocess needs a ProactorEventLoop on Windows; the
        SelectorEventLoop SubdomainX forces on win32 cannot spawn one. Elsewhere
        (Linux/macOS) it is always fine."""
        if sys.platform != "win32":
            return True
        try:
            loop = asyncio.get_event_loop()
            return isinstance(loop, asyncio.ProactorEventLoop)
        except Exception:
            return False

    # ── bulk resolution ──────────────────────────────────────────────────────
    async def resolve(self, fqdns: Iterable[str],
                      wildcard_ips: Optional[Set[str]] = None
                      ) -> Dict[str, Dict[str, List[str]]]:
        """Bulk-resolve *fqdns* with massdns. Returns resolving names only, with
        wildcard-IP hits filtered out. Returns ``{}`` (never raises) if the binary
        is missing or the platform can't spawn it — the caller falls back to
        dnspython."""
        names = [f.strip().rstrip(".") for f in fqdns if f and f.strip()]
        if not names or not self.binary or not self._subprocess_supported():
            return {}

        tmpdir = tempfile.mkdtemp(prefix="sx_massdns_")
        in_path = os.path.join(tmpdir, "in.txt")
        res_path = os.path.join(tmpdir, "resolvers.txt")
        try:
            with open(in_path, "w", encoding="utf-8") as f:
                f.write("\n".join(names) + "\n")
            with open(res_path, "w", encoding="utf-8") as f:
                f.write("\n".join(self.resolvers) + "\n")

            # -o J : ndjson;  -t A : A query (CNAME chain rides along);  -q : quiet
            proc = await asyncio.create_subprocess_exec(
                self.binary, "-r", res_path, "-t", "A", "-o", "J", "-q", in_path,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await proc.communicate()
        except Exception:
            return {}
        finally:
            for p in (in_path, res_path):
                try:
                    os.unlink(p)
                except Exception:
                    pass
            try:
                os.rmdir(tmpdir)
            except Exception:
                pass

        parsed = parse_massdns_ndjson(stdout.decode("utf-8", "ignore") if stdout else "")
        if wildcard_ips:
            parsed = {
                name: rec for name, rec in parsed.items()
                if not (set(rec.get("ips", [])) & wildcard_ips)
            }
        return parsed
