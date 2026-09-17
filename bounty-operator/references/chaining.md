# Chaining — turn a low into a critical

> Single-bug reports get triaged. Chained reports get paid. The severity of a chain is decided by
> **where it ends**, not where it starts. Before reporting any low/medium, run the filter below.

## The 10-question chain filter

Run for every candidate finding before spending more than ~30 minutes on it:

```
Q1.  Cross-user impact?            → IDOR / BOLA family
Q2.  Cross-tenant impact?          → massive multiplier on SaaS
Q3.  Leaks credentials / tokens?   → secret family (esp. cloud / admin)
Q4.  Pre-auth?                     → removes the social-engineering step
Q5.  0-click?                      → removes the user-interaction cost
Q6.  Persistent / stored?          → keeps paying after the report
Q7.  Reaches internal / metadata?  → SSRF chain
Q8.  Reads source / config?        → feeds the next bug
Q9.  Leads to RCE / SQLi / admin?  → critical
Q10. Mass-exploitable?             → dramatic multiplier
```

- **3+ YES** → likely report-worthy on its own; still check whether a chain lifts the tier.
- **1–2 YES** → keep escalating: find the connector gadget before you write it up.

## Common escalation ladders

Use these as templates — the connector is the creative part.

- **Open redirect** → OAuth `redirect_uri` abuse → authorization-code / token theft → **ATO**
- **Reflected/DOM XSS** → steal session or CSRF token → authenticated action → **ATO / privilege change**
- **SSRF** → cloud metadata endpoint → temporary credential → cloud API read → **infra / data exposure**
- **IDOR (read)** → enumerate ids → **mass PII read**; then find the matching **write** IDOR → **cross-tenant modify**
- **Info leak (JS bundle)** → internal endpoint / role flag / API key → **authz bypass or secret abuse**
- **File upload** → path/type bypass → stored payload or web-shell path → **RCE**
- **Sub-route auth skip** → `/orders/{id}` is 403 but `/orders/{id}/refund` is not → **financial impact**
- **JWT weakness** (`alg:none`, RS256→HS256, weak secret) → forge claims → **vertical privilege escalation**
- **CORS wildcard + credentials** → cross-origin read of authenticated responses → **data theft**
- **Request smuggling / cache poisoning** → poison a shared response → **mass 0-click impact**

## The 30-minute chain-or-move clock

For each candidate: spend up to ~30 minutes finding a connector gadget. If the chain reaches a paid
impact, report the chain. If not, log it in the coverage ledger (with *why* it stalled) and move on —
you can return when a new primitive on the same target unlocks it.

## Writing the impact of a chain

- Describe the **end state** first (what the attacker walks away with), then the path.
- Show each hop as a reproducible step; a triager should be able to replay the whole chain.
- Rate severity at the endpoint, and name the attacker, the victim, and the concrete harm.
