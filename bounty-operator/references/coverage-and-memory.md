# Coverage & Memory — never repeat, never skip, always resume

> On real engagements a large share of actions are exact duplicates, and bugs get missed because
> nobody tracked what was already tried. A coverage ledger fixes both. It also lets a session pick
> up exactly where the last one stopped.

## One folder per target

Every artifact for a target lands under that target's own folder. Never invent a scratch directory.

```
targets/<target>/
├── scope.md            # in-scope / out-of-scope, split explicitly
├── ledger.jsonl        # coverage ledger (append-only, one row per test)
├── findings.jsonl      # confirmed + killed findings, each with an F-id
├── loot.jsonl          # creds, tokens, endpoints, anomalies (F-id linked)
├── recon/              # subdomains, live hosts, js, params, screenshots
└── reports/            # drafted submissions
```

## Coverage ledger row (append-only)

Log a row the moment you test something — before you know the outcome, then update it.

```json
{"ts":"2026-09-17T10:00:00Z","surface":"api.example.com/v2/orders/{id}","class":"IDOR",
 "hypothesis":"tenant A reads tenant B order","result":"confirmed|killed|inconclusive",
 "evidence":"F-014","why_dismissed":null,"fid":"F-014"}
```

Rules:
- **Searchable false-positive memory** — a killed finding records *why* it was dismissed, so it is
  never re-tested. A number taken on a degraded/rate-limited session is not evidence; re-take it clean.
- **No duplicate work** — before testing, grep the ledger for the same surface+class.
- **Depth, not breadth-only** — a row per depth rung (see the depth ladder), not one row per class.

## Findings row

```json
{"fid":"F-014","title":"Cross-tenant order read via IDOR","class":"IDOR","status":"confirmed",
 "severity":"High","chain":["F-014","F-020"],"evidence_path":"recon/…","reported":false}
```

## Loot row

```json
{"fid":"F-021","type":"aws_key|jwt|endpoint|internal_host|pii","value_ref":"redacted/stored-locally",
 "source":"js-bundle app.min.js","usable":true,"notes":"scoped to s3 read"}
```
Store the raw sensitive value locally/redacted — keep it out of chat context and out of reports.

## Resume protocol (start of every session)

```
0. Read scope.md, ledger.jsonl, findings.jsonl for this target.
1. List untested surfaces (surface × class not yet in the ledger) → hunt those first.
2. List inconclusive rows → retry with a sharper hypothesis.
3. List confirmed-but-unchained lows → run the chain filter (references/chaining.md).
4. Only then expand recon for new surface.
```

## The stuck loop (instead of concluding "secure")

When a surface looks clean:
```
1. Fingerprint the exact stack / framework / WAF / defense.
2. Research THAT specifically (current year first — old bypasses get patched).
3. Pick a class the defense cannot cover, or craft a defense-specific bypass.
4. Fire one hypothesis-driven probe. Log it. Repeat.
```
No findings means testing is incomplete — never that the target is safe.
