# Changelog

## [Unreleased] — Enumeration upgrade (2026-07-07)

Close the discovery-yield / resolution-speed gap vs bbot/Amass on large targets.
Everything below is **optional with a pure-Python fallback** — SubdomainX still
runs with zero external binaries and zero seeds (standalone CLI). All public
names/signatures the Falcon adapter monkeypatches/reads are preserved.

### Added

- **[0] External seed ingestion** — `SubdomainX.add_seed_subdomains(names)`
  pre-populates `all_subdomains` + a dedicated `seed_subdomains` set (normalized,
  scope-filtered) before the active phases, so the mutation engine learns from
  externally-discovered names (e.g. a caller's CT/passive-DNS results) without
  SubdomainX re-querying passive sources. Seedless-safe.
- **[1] Optional massdns/shuffledns resolver backend** (`resolver_massdns.py`) —
  bulk A/CNAME resolution via the massdns binary when present; `select_backend`
  (`--resolver-backend auto|massdns|dnspython`, default auto) falls back to
  dnspython when the binary is absent (or on the Windows SelectorEventLoop, which
  can't spawn subprocesses). `DNSBruteForcer`/`PermutationScanner`/
  `RecursiveEnumerator` route bulk resolution through it via an attr-injected
  `resolver_backend`, keeping `_resolve_one` as the dnspython fallback. stdlib-only.
- **[2] Target-learned mutation engine** (`mutations.py`) — frequency word cloud
  from all known names (PTR/numeric tokens dropped via `has_excessive_digits`),
  recombined across every parent (bbot dnsbrute_mutations) + numeric padding +
  static affix seeds, deduped by an in-repo `BloomFilter` (<~100MB). Deterministic;
  `max_mutations` cap. `PermutationScanner._generate_permutations` delegates.
- **[3] Loop-until-dry convergence** (`_convergence_phase`) — re-mutates from all
  known names each round with a bloom shared across rounds (never re-emits a
  known/attempted name), stopping after `--mutation-rounds` consecutive empty
  rounds (default 3; 0 disables) or a hard 12-round backstop. Self-contained.
  `RecursiveEnumerator` now honors `max_depth` (breadth-first), uses the shared
  backend, a per-parent wildcard cache, and a configurable `max_recursive_words`
  (was a hardcoded 500-word single pass).
- **[4] Robust wildcard + junk filtering** — `WildcardDetector` gains per-parent
  detection (`detect_parent`, cached), CNAME-wildcard awareness
  (`is_wildcard(ips, cnames=...)`), and `is_junk(name)` to drop PTR-like names.
  One shared detector is reused across all phases (was re-detected each phase).
- **[5] Resolver trust tier** (`validation.py`) — every fast-path hit is
  re-verified on a small trusted-resolver set (Cloudflare/Google/Quad9) before
  acceptance, guarding against DNS poisoning / stale caches. `--no-resolver-
  validation` to disable (ON by default). Verification gates at hit-acceptance
  (`_accept` / `bulk_resolve`), so an integrating tool's live-push sees only
  verified names.

### Tests

62 offline unit tests (`tests/`): seed ingestion, backend selection + massdns
ndjson parse, bulk_resolve routing, mutation engine + bloom, convergence loop +
recursive `max_depth`, per-parent/CNAME wildcard + junk filter, trust-tier
validation. No network; massdns/DNS are stubbed.
