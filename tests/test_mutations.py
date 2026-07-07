"""[2] Target-learned mutation engine — word cloud, bloom dedupe, recombination.

Replaces the static affix list with mutations learned from the target's own names:
tokenize every known name, build a frequency word cloud, and recombine learned
tokens across all parents (bbot dnsbrute_mutations style) + numeric/devops padding.
Deterministic given the same inputs; a bloom filter dedupes attempted names at scale.
"""
from __future__ import annotations

from subdomainx.mutations import (
    has_excessive_digits,
    tokenize,
    build_word_cloud,
    generate_mutations,
    BloomFilter,
)


# ── excessive-digit / PTR-like filtering ─────────────────────────────────────

def test_has_excessive_digits_drops_ptr_like_and_pure_numbers():
    assert has_excessive_digits("01")
    assert has_excessive_digits("192")
    assert has_excessive_digits("1234")
    assert has_excessive_digits("10")


def test_has_excessive_digits_keeps_real_words():
    assert not has_excessive_digits("api")
    assert not has_excessive_digits("s3")     # meaningful, only 1 digit
    assert not has_excessive_digits("v1")
    assert not has_excessive_digits("web")


# ── tokenization ─────────────────────────────────────────────────────────────

def test_tokenize_splits_on_delims_and_strips_domain():
    assert tokenize("dev-api.example.com", "example.com") == ["dev", "api"]
    assert tokenize("api.internal.example.com", "example.com") == ["api", "internal"]


def test_tokenize_drops_numeric_tokens():
    assert tokenize("web-01.example.com", "example.com") == ["web"]  # 01 dropped


def test_tokenize_apex_yields_nothing():
    assert tokenize("example.com", "example.com") == []


# ── word cloud (deterministic frequency) ─────────────────────────────────────

def test_word_cloud_counts_tokens_deterministically():
    names = ["dev-api.example.com", "api-gw.example.com", "api.example.com"]
    wc = build_word_cloud(names, "example.com")
    assert wc["api"] == 3
    assert wc["dev"] == 1
    assert wc["gw"] == 1
    # deterministic: same input → identical ordering of most_common
    assert build_word_cloud(names, "example.com").most_common() == wc.most_common()


# ── bloom filter ─────────────────────────────────────────────────────────────

def test_bloom_add_and_contains_no_false_negatives():
    bf = BloomFilter(capacity=1000)
    for w in ("api.example.com", "dev.example.com", "vpn.example.com"):
        bf.add(w)
    for w in ("api.example.com", "dev.example.com", "vpn.example.com"):
        assert w in bf                       # never a false negative
    assert "totally-absent-xyz.example.com" not in bf   # (probabilistic, but reliable here)


def test_bloom_len_tracks_distinct_adds():
    bf = BloomFilter(capacity=1000)
    bf.add("a"); bf.add("a"); bf.add("b")
    assert len(bf) == 2


# ── mutation generation ──────────────────────────────────────────────────────

def _domain():
    return "example.com"


def test_generates_sibling_recombinations():
    known = {"api.example.com", "dev.example.com"}
    muts = generate_mutations(known, _domain(), static_affixes=["staging"])
    # each sibling's tokens applied to the other parent
    assert "dev-api" in muts or "api-dev" in muts
    # static affix applied
    assert "staging-api" in muts or "api-staging" in muts


def test_excludes_already_known_prefixes():
    known = {"api.example.com", "dev.example.com"}
    muts = generate_mutations(known, _domain())
    assert "api" not in muts and "dev" not in muts


def test_numeric_padding_applied():
    known = {"api.example.com"}
    muts = generate_mutations(known, _domain())
    assert any(m in muts for m in ("api1", "api-1", "api01"))


def test_is_deterministic():
    known = {"api.example.com", "dev-gw.example.com"}
    a = generate_mutations(known, _domain(), static_affixes=["prod"], max_mutations=500)
    b = generate_mutations(known, _domain(), static_affixes=["prod"], max_mutations=500)
    assert a == b


def test_respects_max_mutations_cap():
    known = {f"h{i}x.example.com" for i in range(30)}  # non-numeric tokens
    muts = generate_mutations(known, _domain(), static_affixes=["a", "b", "c"],
                              max_mutations=50)
    assert len(muts) <= 50


def test_bloom_dedupe_skips_already_attempted():
    known = {"api.example.com"}
    bloom = BloomFilter(capacity=100000)
    # Pre-mark a candidate we expect the engine would otherwise produce.
    first = generate_mutations(known, _domain(), static_affixes=["dev"], bloom=bloom)
    assert first  # produced something and recorded into bloom
    # Second pass with the SAME bloom must not re-emit anything already attempted.
    second = generate_mutations(known, _domain(), static_affixes=["dev"], bloom=bloom)
    assert second == set()


def test_empty_known_names_is_empty():
    assert generate_mutations(set(), _domain()) == set()
