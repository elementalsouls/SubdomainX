"""[2] Target-learned mutation engine.

Instead of only combining a fixed affix list with discovered names, learn the
target's own naming vocabulary: tokenize every known name, build a frequency
word cloud, and recombine those learned tokens across every parent (the bbot
``dnsbrute_mutations`` idea) plus numeric/devops padding and a static affix seed
set. A bloom filter dedupes attempted names at scale. Output is deterministic
given the same inputs (sorted iteration throughout), so tests can pin it.

Pure-Python, stdlib only — safe to import with zero external deps.
"""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from typing import Iterable, List, Optional, Set

_DELIM_RE = re.compile(r"[-._]")

# Static affix seed set (kept as a seed only — the learned word cloud is the
# primary source). Consolidated from the historical PermutationScanner lists.
STATIC_AFFIXES: List[str] = [
    # env / lifecycle
    "dev", "development", "staging", "stage", "stg", "test", "qa", "uat",
    "prod", "production", "preprod", "demo", "beta", "alpha", "canary",
    "preview", "sandbox", "lab", "pilot", "edge", "next", "legacy",
    # infra / services
    "api", "app", "web", "www", "mail", "smtp", "vpn", "proxy", "gateway",
    "gw", "lb", "cdn", "cache", "admin", "portal", "dashboard", "panel",
    "auth", "login", "sso", "id", "git", "gitlab", "ci", "cd", "jenkins",
    "registry", "docker", "k8s", "vault", "internal", "external", "corp",
    # cloud
    "aws", "azure", "gcp", "cloud", "s3", "storage", "origin",
    # state / backup
    "new", "old", "backup", "bak", "dr", "replica", "primary", "secondary",
    # data
    "db", "sql", "mysql", "postgres", "mongo", "redis", "data", "warehouse",
]

_NUMERIC_PAD: List[str] = ["1", "2", "3", "0", "01", "02", "03"]

DEFAULT_MAX_MUTATIONS = 100_000


def has_excessive_digits(token: str) -> bool:
    """True for PTR-like / pure-numeric tokens that should not enter the learned
    vocabulary (numbers are re-added separately as padding). Keeps meaningful
    tokens with an incidental digit ("s3", "v1", "web01")."""
    if not token:
        return True
    digits = sum(c.isdigit() for c in token)
    if digits == len(token):          # pure number ("01", "192")
        return True
    if re.search(r"\d{3,}", token):   # 3+ digit run — id / PTR-like
        return True
    if digits / len(token) > 0.6:     # mostly digits
        return True
    return False


def _strip_domain(name: str, domain: str) -> str:
    name = (name or "").strip().lower().rstrip(".")
    domain = (domain or "").strip().lower().rstrip(".")
    if not name or name == domain:
        return ""
    suffix = "." + domain
    if name.endswith(suffix):
        return name[: -len(suffix)]
    return ""  # out of scope — ignore


def tokenize(name: str, domain: str) -> List[str]:
    """Sub-tokens of *name*'s prefix (domain stripped), split on [-._], with
    PTR-like / numeric tokens dropped. Order-preserving."""
    prefix = _strip_domain(name, domain)
    if not prefix:
        return []
    return [t for t in _DELIM_RE.split(prefix) if t and not has_excessive_digits(t)]


def build_word_cloud(names: Iterable[str], domain: str) -> Counter:
    """Frequency Counter of learned tokens across *names*. Deterministic: names
    are visited in sorted order so ``most_common`` tie-ordering is stable."""
    cloud: Counter = Counter()
    for n in sorted(set(names)):
        for tok in tokenize(n, domain):
            cloud[tok] += 1
    return cloud


class BloomFilter:
    """Compact bit-array bloom filter for deduping attempted names at scale.

    No false negatives; a tunable small false-positive rate. Sized from *capacity*
    and *error_rate*, hard-capped so the bit array stays well under ~100MB."""

    _MAX_BITS = 800_000_000  # ~100MB

    def __init__(self, capacity: int = 1_000_000, error_rate: float = 0.001):
        capacity = max(1, int(capacity))
        m = int(-capacity * math.log(error_rate) / (math.log(2) ** 2))
        m = max(8, min(m, self._MAX_BITS))
        self.size = m
        self.k = max(1, int(round((m / capacity) * math.log(2))))
        self.bits = bytearray((m + 7) // 8)
        self._count = 0

    def _positions(self, item: str):
        data = item.encode("utf-8", "ignore") if isinstance(item, str) else bytes(item)
        h1 = int.from_bytes(hashlib.blake2b(data, digest_size=8).digest(), "big")
        h2 = int.from_bytes(hashlib.blake2b(data + b"\x00", digest_size=8).digest(), "big") | 1
        for i in range(self.k):
            yield (h1 + i * h2) % self.size

    def __contains__(self, item) -> bool:
        return all((self.bits[p >> 3] >> (p & 7)) & 1 for p in self._positions(item))

    def add(self, item) -> bool:
        """Add *item*; return True if newly added, False if already present."""
        if item in self:
            return False
        for p in self._positions(item):
            self.bits[p >> 3] |= 1 << (p & 7)
        self._count += 1
        return True

    def __len__(self) -> int:
        return self._count


def generate_mutations(
    known_names: Iterable[str],
    domain: str,
    static_affixes: Iterable[str] = (),
    max_mutations: int = DEFAULT_MAX_MUTATIONS,
    bloom: Optional[BloomFilter] = None,
    extra_tokens: Iterable[str] = (),
) -> Set[str]:
    """Generate candidate subdomain *prefixes* learned from *known_names*.

    - Learn a frequency word cloud from the known names.
    - Apply every affix (static seed + learned tokens + extras) to every parent
      (hyphen / concat / dotted, both orders).
    - Numeric/devops padding per parent.
    Already-known prefixes are excluded; if a *bloom* is passed, every emitted
    prefix is recorded and anything already in it is skipped (loop-until-dry
    dedupe across rounds). Deterministic; capped at *max_mutations*."""
    known_norm = {(n or "").strip().lower().rstrip(".") for n in known_names if n}
    parents = sorted({_strip_domain(n, domain) for n in known_norm} - {""})
    if not parents:
        return set()
    known_prefixes = set(parents)

    cloud = build_word_cloud(known_norm, domain)
    learned = [t for t, _ in cloud.most_common()]
    # ordered, de-duplicated affix list: static seeds first, then extras, then
    # frequency-ranked learned vocabulary.
    affixes = list(dict.fromkeys(
        [a.lower() for a in static_affixes]
        + [t.lower() for t in extra_tokens]
        + learned
    ))

    out: Set[str] = set()

    def _emit(prefix: str) -> None:
        if not prefix or prefix in known_prefixes or prefix in out:
            return
        if bloom is not None:
            if prefix in bloom:
                return
            bloom.add(prefix)
        out.add(prefix)

    for parent in parents:
        for affix in affixes:
            if affix == parent:
                continue
            for cand in (
                f"{affix}-{parent}", f"{parent}-{affix}",
                f"{affix}{parent}", f"{parent}{affix}",
                f"{affix}.{parent}", f"{parent}.{affix}",
            ):
                _emit(cand)
                if len(out) >= max_mutations:
                    return out
        for pad in _NUMERIC_PAD:
            for cand in (f"{parent}{pad}", f"{parent}-{pad}",
                         f"{pad}-{parent}", f"{pad}{parent}"):
                _emit(cand)
                if len(out) >= max_mutations:
                    return out
    return out
