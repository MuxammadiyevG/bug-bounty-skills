# Reporting — impact-first, anchored, copy-pasteable

> A triager reads 50–200 reports a day and gives yours ~10 minutes. Reproduction must be
> copy-pasteable, impact plain, severity honest, tone clean, and everything about the researcher
> cut. Lead with what the attacker walks away with.

## Title formula

`[Impact] via [Vulnerability] in [Component/Endpoint]`
e.g. *"Cross-tenant PII read via IDOR in GET /api/v2/orders/{id}"*

## Standard report template

```markdown
# [Title]

## Summary
One or two sentences: who the attacker is, what they do, and the concrete harm.

## Severity
[Critical/High/Medium/Low] — anchored metric-by-metric (AV/PR/UI/S/CIA). If it's a chain,
rate the endpoint and note the chain. No hedging language.

## Steps to Reproduce
1. Setup: [accounts/tokens needed — attacker's own]
2. [exact HTTP request — method, URL, headers, body, copy-paste ready]
3. [exact response proving impact — the other user's data / the executed payload / the OOB hit]
4. [repeat / escalate as needed]

## Impact
The real-world consequence, stated plainly. Who is affected and at what scale.
If chained, describe the end state first, then the path.

## Proof of Concept
[Redacted screenshots / request-response captures / OOB logs. Minimum data to prove impact.]

## Remediation
Short, concrete fix aligned to the root cause (authorization check at the resolver, etc.).
```

## Platform notes

- **HackerOne** — impact-first summary; attach clean HTTP captures; map to a weakness (CWE) accurately.
- **Bugcrowd** — anchor to the **VRT**; if you believe the default rating undersells the real impact, argue it explicitly with the chain/impact evidence rather than just asserting a higher P-level.
- **Intigriti / YesWeHack** — follow the program's severity model; include business impact.
- **Immunefi (web3)** — PoC-first; a runnable PoC (e.g. Foundry test) usually decides the tier.
- **Always** — dedup against the program's disclosed/hacktivity history before writing.

## Evidence hygiene (do this every time)

- Redact **cookies, Authorization headers, tokens, API keys, and session ids** from every screenshot and capture.
- Redact **victim PII** — prove with one masked record + a count, never a bulk dump.
- Crop out unrelated tabs, extensions, internal tooling, and anything identifying beyond what's needed.
- Store raw sensitive values locally (see coverage-and-memory.md), never paste them into the report body.

## Out-of-scope / N/A rebuttals

If a triager marks something out-of-scope or N/A that you believe is valid, respond once, calmly,
with: the exact in-scope asset, the reproduced impact, and the accepted-impact line it maps to.
If it genuinely fails the 7-Question Gate, accept it and move on — protecting your validity ratio
is worth more than winning one borderline call.
