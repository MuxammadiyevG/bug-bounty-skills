# Authentication Bypass & Session Flaws

> You reach a state or an account you shouldn't — no creds, wrong creds, or a broken token. Direct path to ATO, the highest-paid outcome.

## Root cause
Auth logic trusts something the attacker controls: a reset token that isn't bound to the account, a session that isn't rotated at login, a JWT whose signature isn't verified, or a step in a multi-step flow that can be skipped. The gap: "the earlier step proved identity" — but each step must re-verify.

## Where it hides
- Password reset: token in the response body/URL, predictable/reusable token, `email`/`user_id` parameter accepted alongside the token, host-header poisoning of the reset link.
- Registration/verification: skip email verification, register an already-taken identity, confirm someone else's email.
- Session: no rotation post-login (fixation), long-lived tokens after logout/reset, `remember-me` cookies not invalidated.
- JWT: `alg:none`, RS256→HS256 confusion, weak HMAC secret, `kid` path/SQLi injection, `jku`/`x5u` pointing to attacker keys.
- MFA/OTP: no rate limit, bypass by dropping the second-step request, response manipulation (`"mfa":false`), reusable/predictable OTP, backup-code flaws.
- Step skipping / forced browsing to post-auth endpoints.

## Detection
- Two accounts. Reset A's password; inspect the token — is it in the body? bound to A only? reusable? Try it against B.
- Change the `Host`/`X-Forwarded-Host` on reset request; check where the emailed link points.
- Decode every JWT; test `alg:none`, strip signature, re-sign with HS256 using the RS256 public key, brute weak secrets (`jwt_tool`, `hashcat`).
- Login, capture session; log in again — did the id rotate? Log out — is the old id dead?
- OTP: replay the verify request 100× (no lockout?), tamper the JSON response on the client, skip the step entirely.

## Minimum-evidence bar
You **authenticate as / act as another account** you don't own the creds for, or reach a post-auth state without valid auth — demonstrated end to end. Mirror `../../references/validation-gate.md`: a reflected token, a "weak" policy, or a theoretical `alg:none` without a forged token accepted by the server is not proof. Prove takeover on a second account **you control**.

## Depth ladder
1. Reset-token leak/reuse → set a known password on the victim account.
2. Host-header poisoning → reset link to your domain → capture token.
3. JWT: `alg:none` / signature strip accepted → forge `sub`/`role`.
4. RS256→HS256 confusion using the public key as HMAC secret → forge claims.
5. Session fixation: plant a session id pre-login, victim logs in, you inherit it.
6. MFA bypass: drop step, response tamper, OTP brute, backup-code enumeration.
7. `kid`/`jku`/`x5u` injection → point verification at a key you control.
8. OAuth/OIDC token flaws → see `oauth-oidc.md`.

## Bypass notes
- Rate limit on reset/OTP → rotate IP (`X-Forwarded-For`), casing of email, add whitespace/dots to route around per-account counters.
- JWT filters: `alg:None`/`nOne` casing, embedded JWK header (`jwk`), nested/`typ` confusion.
- Reset token entropy: timestamp/`md5(email)`/sequential — predict offline. See `../bypass-tables.md` for MFA-bypass matrix.

## Chain potential
Host poisoning → ATO. IDOR on `user_id` in reset → ATO. JWT `role` forge → vertical priv-esc → admin. Session fixation + open redirect → 0-click. See `../../references/chaining.md`.

## Real paid example
Real disclosed reports:
- **Account Takeover via Password Reset without user interactions** (GitLab, $35,000) — hackerone.com/reports/2293343 — a reset flow reached full takeover with zero victim interaction; the token/flow wasn't bound to the account it claimed to reset.
- **Account takeover via leaked session cookie** (HackerOne, $20,000) — hackerone.com/reports/745324 — a leaked session cookie was accepted as-is; the session wasn't tied to anything the attacker couldn't replay.
- **Improper Authentication - any user can login as other user with otp/logout & otp/login** (Snapchat, bounty undisclosed) — hackerone.com/reports/921780 — the otp/login step trusted a prior step's identity, so logging out and back in logged you in *as someone else*.
- **Bypass Password Authentication for updating email and phone number** (X / xAI, bounty undisclosed) — hackerone.com/reports/770504 — a sensitive change endpoint never re-verified the password it claimed to require, so the re-auth gate was skippable.

**The recurring tell:** a later step trusts that an earlier step already proved identity (reset token not bound to the account, session cookie replayed, re-auth gate never re-checked) — each case is a step that should re-verify and doesn't, landing directly on ATO.

## Rejected variants
- "Weak password policy" / "no rate limit" with no demonstrated takeover.
- `alg:none` accepted by a decoder library locally but rejected server-side.
- Logout CSRF, self password change.
- Username enumeration alone (informative unless it feeds a real bypass).
- MFA "bypass" that still requires the victim's valid password you don't have.
