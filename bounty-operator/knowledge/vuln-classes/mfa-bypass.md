# MFA / 2FA Bypass

> Reach the authenticated state without the second factor. Seven recurring patterns. It's ATO-tier
> when the first factor is already known or phishable.

## Root cause
The second factor is enforced by the client or by one code path but not another. The server either
trusts a client-side signal, skips verification on an alternate flow, or fails to rate-limit / bind /
invalidate the OTP. The account is protected in the happy path only.

## Where it hides
- The step *after* password entry (the "enter your code" transition).
- Alternate auth paths: mobile API, legacy endpoint, OAuth/social login, SSO, password-reset,
  "remember this device", account-recovery, backup codes.
- Response bodies that carry a `success`/`mfaRequired` flag the client reads.

## Detection — the seven patterns
1. **Response manipulation** — flip `"mfaRequired":true`→`false`, `"success":false`→`true`, or a
   403→200 on the verify response; see if the session upgrades to fully authenticated.
2. **Skip the step / direct-object** — after password, request the post-MFA endpoint directly; the
   verify step is never enforced server-side.
3. **Backup-code / OTP brute** — no rate limit or lockout on the 6-digit code; exhaust the space or
   the finite backup-code set.
4. **Remember-device abuse** — the "trusted device" token is guessable, not bound to the account, or
   reusable across accounts; forge/replay it to skip MFA.
5. **Code reuse / no invalidation** — the OTP stays valid after use, after expiry, or across sessions;
   or the same code works for a different user.
6. **Race condition** — submit many verify attempts concurrently to beat a single-use/rate check, or
   race enable/disable MFA to desync state.
7. **Flow-swap / alternate factor** — disable MFA, downgrade to a weaker factor, or use a
   reset/recovery/OAuth path that doesn't demand the second factor.

## Minimum-evidence bar
You reach the fully authenticated account state **without** a valid second factor, shown by accessing
a post-MFA resource or completing a sensitive action — not a 200 on the verify call alone. For brute:
the actually-accepted code and the resulting authenticated session. Prove access to one protected
resource, then stop. Test only accounts you control (two you own for cross-account cases).

## Depth ladder
1. Confirm the second factor is enforced in the happy path (baseline).
2. Try patterns 1–2 (cheapest: response tamper, step skip).
3. Try 3–5 (brute, remember-device, reuse).
4. Try 6–7 (race, flow-swap) — highest effort.
See `../payloads/idor.md` for the direct-object methodology behind pattern 2.

## Bypass notes
- Rate limit on verify → distribute across IPs/sessions, or find the alternate endpoint without it.
- Lockout counter client-side only → server accepts unlimited attempts.
- Remember-device token → test cross-account replay and predictability. See `../bypass-tables.md`.

## Chain potential
MFA bypass turns a known/leaked/phished password into full **ATO**. Combine with a credential-stuffing
or password-reset weakness to remove the first-factor dependency entirely. See
`../../references/chaining.md`.

## Real paid example
After correct password, the MFA verify endpoint returned `{"verified":false}` and the SPA gated on it.
Intercepting and flipping it to `true` upgraded the session to fully authenticated — the server never
re-checked the factor when serving account data. Response-manipulation MFA bypass, proven by loading
the protected dashboard. Rough band: $3k–$10k (ATO-tier with a known password).

## Rejected variants
- Flipping the response flip is cosmetic — the server still blocks protected resources. Not a bypass.
- Brute "works" against your own throwaway with a 10-minute code window and low entropy but a real
  lockout in place — no actual bypass.
- "MFA can be disabled from settings while logged in" — that's expected behavior, not a bypass.
- Bypass only after already holding a valid session for that account — no privilege gained.
