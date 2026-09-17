# API Misconfiguration

> Mass assignment, JWT attacks, prototype pollution, and CORS. The API works "correctly" — the misconfig is what it *accepts* or *trusts*. High volume, high payout.

## Root cause
Four distinct failures, one theme — trusting client-supplied structure:
- **Mass assignment (BOPLA):** handler binds the whole request body to a model, so hidden fields
  (`role`, `isAdmin`, `price`, `tenantId`, `verified`, `balance`) are writable.
- **JWT:** verification is weak — `alg:none` accepted, RS256↔HS256 confusion (public key used as HMAC
  secret), weak/guessable HMAC secret, `kid` path traversal/SQLi, unverified `jku`/`x5u`, missing
  expiry/audience checks, mutable claims.
- **Prototype pollution:** merge/clone of user JSON writes `__proto__`/`constructor.prototype`,
  poisoning every object → auth flag flip, gadget-driven RCE (server) or XSS (client).
- **CORS:** origin reflected into `Access-Control-Allow-Origin` with `Allow-Credentials: true`, or a
  broken allowlist (suffix/substring match, `null` origin) → cross-origin authenticated read.

## Where it hides
- User/profile/settings/org PATCH & POST bodies (mass assignment).
- Any Bearer token, session cookie JWT, OAuth/OIDC ID token, password-reset token.
- Config-merge, query-builder, and deep-merge utilities (`lodash.merge`, `Object.assign` loops).
- Every endpoint that echoes `Origin` — check credentialed ones especially.

## Detection
- Mass assignment: add plausible privileged fields to a working request; diff the response/state.
  Read a GET response first to learn field names, then try to write them.
- JWT: decode header; try `alg:none`, sign with the public key as HMAC secret, brute weak secrets
  offline, tamper a claim and see if it's honored.
- Prototype pollution: send `{"__proto__":{"polluted":"x"}}` / `constructor.prototype.x`; probe a
  reflected property or a known gadget behavioral change.
- CORS: send `Origin: https://evil.tld`, then `null`, then `target.tld.evil.tld` — check reflection
  *and* `Allow-Credentials`.

## Minimum-evidence bar
The privilege/state actually changed or the cross-origin secret is actually readable — not a 200,
not a reflected header alone. JWT: you reach a state/account you shouldn't (forged claim honored).
CORS: a working PoC page reading an authenticated response cross-origin, not just the reflected
header. Prototype pollution: a demonstrated downstream effect (auth flip, gadget). Prove once, stop.

## Depth ladder
1. Mass assignment: flip `role`/`isAdmin`/`verified` → privilege escalation.
2. JWT: forge admin claims via alg confusion / weak secret → vertical priv-esc.
3. Prototype pollution: property flip → auth bypass, then hunt a gadget → RCE/XSS.
4. CORS wildcard+creds → build the exfil page → data theft.
See `../payloads/idor.md` for the authz-testing methodology that pairs with mass assignment.

## Bypass notes
- CORS allowlist by suffix → `target.tld.evil.tld`; by substring → `eviltarget.tld`; `null` via
  sandboxed iframe/`data:`. JWT `kid` → point at a predictable file or inject. See `../bypass-tables.md`.

## Chain potential
Mass assignment `tenantId` → cross-tenant write. JWT forge → BFLA admin functions. Prototype
pollution → RCE gadget or DOM XSS → ATO. CORS → session read → ATO. See `../../references/chaining.md`.

## Real paid example
A profile-update PATCH accepted a `role` field never shown in the UI. Sending `"role":"admin"` on a
free account promoted it; proven by then calling an admin-only export as that account. Mass assignment
→ vertical privilege escalation. Rough band: $5k–$15k.

## Rejected variants
- CORS header reflected but `Allow-Credentials` is false and the data is public — no theft path.
- JWT tampering rejected (signature actually verified) — decoding a token is not a bug.
- Mass assignment of a harmless field (display name) with no privilege/logic effect.
- Prototype pollution with no reachable gadget and no security-relevant property affected.
