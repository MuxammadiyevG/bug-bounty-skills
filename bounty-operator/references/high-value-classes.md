# High-Value Classes — where the payouts actually are

> Prioritize by expected value, not by what's easy to scan. This file gives, per class: what it is,
> the minimum evidence that makes it real, and why a triager pays. For deep per-class technique and
> payloads, load the matching specialist skill (`per-class-index.md`). The dated "technique radar" at
> the end is time-sensitive — refresh it periodically.

## The priority ladder (top = hunt first)

### 1. Authorization failures (the #1 API risk class, the bulk of real payouts)
- **BOLA / IDOR (object-level).** Endpoint authenticates you but doesn't check the object is yours.
  *Evidence:* another user's/tenant's real data in the body, with two accounts you control. Not a 200,
  not a reflected id. *Why paid:* direct data breach; enumerable → mass PII.
  *Note:* UUIDs hide enumeration but do **not** enforce access control — still test them. Test READ, then WRITE.
- **BFLA (function-level).** Low-privilege principal invokes an admin-only function/mutation.
  *Evidence:* the privileged action succeeds from the low-priv account. *Why paid:* privilege escalation.
- **BOPLA (property-level).** Over-returned fields (excessive data exposure) or accepted hidden fields
  (mass assignment: role, isAdmin, price, tenantId). *Evidence:* sensitive field read you shouldn't
  see, or a hidden field write that changes state. *Why paid:* data exposure or privilege/logic change.
- **Cross-tenant read/write.** Any of the above across the tenant wall (exports, search, caches,
  webhooks, PDF gen). *Why paid:* SaaS multiplier — one bug, every customer.

### 2. Business-flow abuse (no "bug" at all — the API works as designed, abused at scale)
Sensitive flows (checkout, coupon, referral, rate-limited actions, resource creation) with no
anti-automation. *Evidence:* the flow completed in a way/at a scale it shouldn't (free purchase,
infinite credit, resource exhaustion). *Why paid:* direct financial/impact; scanners never model it.

### 3. Authentication / session / ATO
Password reset flaws, session fixation, JWT abuse (alg confusion, weak secret, mutable claims),
MFA/2FA bypass, OAuth/OIDC flow abuse. *Evidence:* you reach a state or another account you shouldn't.
*Why paid:* account takeover is top-tier.

### 4. SSRF
User-controlled URL fetched server-side. *Evidence:* an OOB callback you control, or an internal-only
response body — a hung request is not proof. *Why paid:* pivots to cloud metadata → credentials →
infra/data (a prime chain root).

### 5. Injection & code execution
SQLi/NoSQLi, SSTI, deserialization, file-upload→RCE, command injection. *Evidence:* differential/
time/OOB proof or controlled execution — via authorized, non-destructive probing; never dump real
user data. *Why paid:* high to critical; frequently the end of a chain.

### 6. Client-side & protocol
XSS (must *execute*, not just reflect), CORS weaponization, CSWSH, request smuggling, cache
poisoning, prompt injection into AI features. *Evidence:* concrete harm (token theft, state change,
mass 0-click), not the primitive alone. *Why paid:* varies; often chains into ATO or mass impact.

## The universal evidence discipline

For every class: prove **impact**, with the **minimum data** needed (one record, one key, one field),
then **stop**. A correct-looking 200 is the default for high-value API bugs — status codes are never
proof. Route each confirmed finding through the Validation Gate, the chain filter, and the ledger.

---

## Technique radar — TIME-SENSITIVE, refresh periodically

> This is a snapshot of research directions worth watching, not an evergreen list. Re-check
> PortSwigger's annual "Top 10 Web Hacking Techniques", the OWASP API Top 10, and current disclosed
> reports, and update this section. Treat entries as *leads to research on the fingerprinted stack*,
> never as copy-paste payloads.

Recent high-signal directions (mid-2020s):
- **Authorization-first everything** — object/function/property-level authz remain the dominant paid
  class; business-flow abuse (abuse-as-designed) is now a first-class category.
- **OAuth/OIDC flow attacks** — authorization-code injection, response-mode/redirect manipulation,
  and BFF/PKCE edge cases.
- **Parser differentials** — the same input interpreted two ways across parsers/proxies (email atom,
  cookie/`$Version`, HTTP/2 quirks) → auth bypass, WAF bypass, smuggling.
- **Cross-site WebSocket hijacking** via WebSocket-reachable GraphQL, bypassing preflight-gated CSRF.
- **CORS weaponization** — reflected/alternate-origin trust enabling authenticated data exfil.
- **Error-based & ORM-driven server-side injection** (SSTI/ORM leak) resurfacing in new frameworks.
- **AI-feature attack surface** — prompt injection into agentic/CI features leading to tool abuse and
  secret exfiltration; a fast-growing, often-unmodeled surface.
- **XS-Leaks** — chaining individually-harmless side channels into cross-site oracles.

The meta-lesson from every annual list: novel bugs come from *curiosity at the boundaries* — where a
protocol, parser, or framework quietly disagrees with itself — not from re-running known payloads.
