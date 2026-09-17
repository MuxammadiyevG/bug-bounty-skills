# OAuth / OIDC Flow Attacks

> Steal an authorization code or token, or swap an identity, by abusing the redirect/exchange dance. One loose `redirect_uri` = 0-click ATO.

## Root cause
The authorization server or the relying party trusts a value it shouldn't: a `redirect_uri` matched loosely, a `state` not checked (CSRF), an ID token accepted without verifying `iss`/`aud`/signature, or an account linked by unverified email. The gap: "the provider handled auth, so whatever comes back is trustworthy."

## Where it hides
- `redirect_uri` validation on the `/authorize` endpoint (loose prefix/substring/subdomain match, open path, `//`, userinfo tricks).
- `state` parameter absent or unvalidated → login CSRF / code injection.
- `response_type`/`response_mode`: leaking token in the fragment, `form_post` to wrong origin.
- PKCE: missing, downgradeable, or `code_verifier` not enforced (public clients).
- Code/token exchange: code reuse, code from one client accepted by another (mix-up), cross-account code injection.
- Account linking: link social identity by email without verification → pre-account-takeover.
- ID token: unverified `iss`/`aud`/`nonce`/signature, `alg:none` (see auth-bypass.md).

## Detection
- Tamper `redirect_uri`: append path, swap to a controlled subdomain, add `@`, `#`, `.attacker.com`, extra params, `%2f`, open-redirect on an allow-listed host.
- Remove/reuse `state` — does login complete? Replay a code — is it single-use?
- Check for PKCE (`code_challenge`); try dropping it or using `plain`.
- Inspect the ID token: is signature/`aud`/`iss` actually verified by the RP? Swap in a token from another client.
- Watch where the `code`/token lands (Referer leak, fragment, redirect chain).

## Minimum-evidence bar
You **capture a victim's authorization code/token and use it to authenticate as them**, or you log into a victim account via identity confusion — end to end, on a second account you control. Mirror `../../references/validation-gate.md`: an open `redirect_uri` alone is a primitive; show the code/token theft and the resulting session. `state` missing without a demonstrated login-CSRF/theft is informative.

## Depth ladder
1. Loose `redirect_uri` → redirect the code to your host → exchange → **ATO**.
2. Open redirect on an allow-listed callback host → same, laundered through a trusted origin.
3. `state` missing → login CSRF, or attach victim's code to your session.
4. Code injection / mix-up: feed a code obtained via your client to the victim's session/another client.
5. PKCE downgrade/omission on a public client → intercepted code is exchangeable.
6. ID-token forgery: unverified `aud`/`iss`/signature → impersonate.
7. Unverified-email account linking → pre-hijack the victim's future SSO login.
See open-redirect payloads in `../payloads/ssrf.md`/`../bypass-tables.md`.

## Bypass notes
- `redirect_uri` matcher: `https://legit.com.attacker.com`, `https://legit.com@attacker.com`, `https://attacker.com/legit.com`, `//attacker.com`, path-append if prefix-matched, `%23`/`%2f`/double-encoding, IDN/case. See `../bypass-tables.md` (open-redirect + SSRF IP tables share tricks).
- Fragment token leak → dangling-markup / Referer exfil on the callback page.

## Chain potential
Open redirect → OAuth code theft → **ATO**. XSS on callback → token exfil. Subdomain takeover of an allow-listed callback host → code theft. See `../../references/chaining.md`.

## Real paid example
Real disclosed reports:
- **Ability to DOS any organization's SSO and open up the door to account takeovers** (Superhuman, $10,500) — hackerone.com/reports/976603 — breaking an org's SSO forces fallback auth that enables ATO.
- **Stealing SSO Login Tokens (snappublisher.snapchat.com)** (Snapchat, $7,500) — hackerone.com/reports/265943 — SSO login token captured cross-origin.
- **Ability to bypass email verification for OAuth grants results in accounts takeovers on 3rd parties** (GitLab, $3,000) — hackerone.com/reports/922456 — unverified-email account linking pre-hijacks victim SSO.
- **Stealing Users OAuth authorization code via redirect_uri** (pixiv, $2,000) — hackerone.com/reports/1861974 — loose `redirect_uri` leaks the `code` to an attacker host.
- **OAuth `redirect_uri` bypass using IDN homograph attack resulting in user's access token leakage** (Semrush, bounty undisclosed) — hackerone.com/reports/861940 — homograph domain passes the callback allowlist.

**The recurring tell:** the AS/RP trusts something it never verified — a loosely matched `redirect_uri`, an unverified email on account link, or an SSO token that leaks cross-origin. The primitive only pays once you drive it to a captured code/token and a real session.

## Rejected variants
- Open `redirect_uri` with no code/token actually captured or exchanged.
- Missing `state` with no login-CSRF or theft demonstrated.
- `alg:none` on an ID token the RP still rejects.
- Account linking to an already-verified email (works as intended).
- Redirect only to same-origin paths (no exfil).
