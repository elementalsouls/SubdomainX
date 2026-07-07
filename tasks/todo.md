# SubdomainX enumeration upgrade (2026-07-07)

Close the yield/speed gap vs bbot/Amass. Cross-repo: code in `L:\Research\SubdomainX`
(this repo, own git/master), adapter in `L:\Research\Falcon-Recon\falcon_recon\modules\subdomain.py`.

## HARD CONSTRAINTS (verified in code)
- Keep intact (Falcon adapter monkeypatches/reads): `DNSBruteForcer.__init__(domain,wordlist_path,
  wildcard_detector,concurrency,callback)`, `DNSBruteForcer._resolve_one(word,sem)`,
  `PermutationScanner._resolve_one(prefix,sem)`, phase methods `_passive_phase.._resolve_phase`,
  attrs `all_subdomains`(set)/`resolved_info`(dict)/`source_counts`(dict), `getattr(self,'max_words',None)`.
- Any signature change → update adapter in SAME change + CONTEXT.md §10.
- Everything new OPTIONAL w/ pure-Python fallback; runs w/ zero binaries + zero seeds.
- Respect Windows SelectorEventLoop 512-FD cap: speed from native resolver path, NOT higher win32 async-DNS concurrency.
- No new hard deps in import path; guard optional deps behind try/import + flags.

## ITEMS (priority order, each own commit + tests) — ALL DONE
- [x] [0] Seed ingestion — SubdomainX 10100fc / Falcon 9fe2646. add_seed_subdomains + _seed_from_graph. 8+4 tests.
- [x] [1] massdns/shuffledns backend — SubdomainX b0ff042 / Falcon 73a64bb. resolver_massdns.py + bulk_resolve routing. 19 tests.
- [x] [2] Target-learned mutation engine — SubdomainX a96319f. mutations.py + BloomFilter; _generate_permutations delegates. 15 tests.
- [x] [3] Loop-until-dry + recursive max_depth — SubdomainX 0c709b5 / Falcon c018ca0. _convergence_phase + RecursiveEnumerator rewrite. 6 tests.
- [x] [4] Robust wildcard + junk filter — SubdomainX 2523f15. per-parent/CNAME WildcardDetector + is_junk; shared detector. 7 tests.
- [x] [5] Resolver trust tier — SubdomainX 29d9a9f / Falcon 0fc7358. validation.py + _accept gating. 7 tests.

## REVIEW
- 62 SubdomainX unit tests green (all offline; massdns + DNS stubbed). 68 Falcon subdomain tests green. Falcon recall gate green (no HTTP-detector regression).
- Constraint gate PASSED (param-level): DNSBruteForcer.__init__ / _resolve_one, PermutationScanner._resolve_one signatures unchanged; all six phase methods + new _convergence_phase present; all_subdomains/resolved_info/source_counts/max_words intact.
- Windows path stays dnspython (massdns absent) → 512-FD cap untouched, verified on this box.
- CHANGELOG.md (both repos) + CONTEXT.md §10 updated (config knobs + T-SUBX-1/2 follow-up tickets).
- NOT run here: live before/after YIELD delta on a real target — needs a Linux box with massdns + network (the massdns/convergence gains are runtime/OS-dependent; wiring + fallbacks verified offline). Recall harness measures HTTP detectors, not subdomain yield, so it can't quantify the delta.

## OUT OF SCOPE (file as CONTEXT.md §10 follow-up tickets)
- wayback (stage 2) + web_pivot (stage 4) emit new hostnames a SubdomainX-internal loop can't see
  (stage ordering) — Falcon orchestrator re-mutation concern, separate ticket.
- js_deep / web_crawl extract hostnames but never emit SUBDOMAIN assets — Falcon-side emission fix, separate ticket.

## VERIFY
- Unit tests: mutation engine (deterministic), bloom filter, per-parent wildcard, backend selection, [0] seed ingest.
- Offline fixture: loop-until-dry converges + never re-emits known names.
- Falcon recall harness before/after: `falcon-recon recall --require-all`; net-new subs + regressions.
- E2E: STANDARD Falcon scan — 6 phases drive, live `found` moves, monkeypatch targets still exist, stage-1 seeds ingested.
- CHANGELOG + CONTEXT.md §10 (new config knobs + 2 out-of-scope tickets).

## REVIEW
(per item)
