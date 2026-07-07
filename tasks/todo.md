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

## ITEMS (priority order, each own commit + tests)
- [ ] [0] Accept external seed subdomains — `SubdomainX.add_seed_subdomains(names)` pre-populates
      all_subdomains + mutation corpus before active phases; adapter seeds from ctx.graph stage-1 sub: assets.
- [ ] [1] Optional massdns/shuffledns resolver backend (biggest speed win) — resolver_massdns.py,
      config resolver_backend auto|massdns|dnspython (default auto), dnspython fallback + single re-verify.
- [ ] [2] Target-learned mutation engine — mutations.py (word-cloud from known names, recombine, bloom dedupe);
      PermutationScanner._generate_permutations delegates (keep signatures). max_mutations cap.
- [ ] [3] Loop-until-dry — convergence loop around brute+perm+recursive (mutation_rounds default 3);
      RecursiveEnumerator honors max_depth + shared resolver backend.
- [ ] [4] Robust wildcard + junk filtering — per-parent WildcardDetector (cached, CNAME-aware),
      has_excessive_digits() to drop PTR-like noise; one detector reused across phases.
- [ ] [5] Resolver trust tier — re-verify every hit on a small trusted-resolver set before adding
      to all_subdomains (config resolver_validation default on).

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
