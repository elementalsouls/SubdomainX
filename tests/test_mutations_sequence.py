"""Sequence enumeration — a numbered known name (esec01) implies the whole
sequence (esec, esec02, esec03, …). Regression guard for the gap surfaced by the
Shree Cement rescan: seed {esec01,esec02} formerly produced NO esec03/esec stem."""
from __future__ import annotations

from subdomainx.mutations import generate_mutations, _number_stem, STATIC_AFFIXES


def test_number_stem():
    assert _number_stem("esec01") == "esec"
    assert _number_stem("sales2") == "sales"
    assert _number_stem("sales-2") == "sales"
    assert _number_stem("shreemail04") == "shreemail"
    assert _number_stem("esec") is None      # no trailing number
    assert _number_stem("01") is None        # all digits
    assert _number_stem("a1") is None        # stem too short


def test_sequence_enumerated_from_numbered_members():
    # passive knows only esec01 + esec02 (NOT the digitless stem)
    perms = generate_mutations(
        {"esec01.shreecementltd.com", "esec02.shreecementltd.com"},
        "shreecementltd.com", static_affixes=STATIC_AFFIXES, max_mutations=100000)
    # the stem and the un-seen siblings must now be generated
    for w in ("esec", "esec03", "esec04", "esec05", "esec3", "esec09"):
        assert w in perms, f"{w} missing — sequence enumeration failed"
    # already-known members are excluded
    assert "esec01" not in perms and "esec02" not in perms


def test_sequence_from_single_member():
    perms = generate_mutations(
        {"sales2.example.com"}, "example.com",
        static_affixes=(), max_mutations=100000)
    assert "sales" in perms
    assert "sales3" in perms and "sales1" in perms
    assert "sales2" not in perms  # the seed itself is a known prefix


def test_non_numbered_names_unaffected():
    # a plain base still gets the normal numeric padding, no stem logic needed
    perms = generate_mutations(
        {"api.example.com"}, "example.com", static_affixes=(), max_mutations=100000)
    assert "api1" in perms and "api01" in perms
    assert "api" not in perms  # the seed itself
