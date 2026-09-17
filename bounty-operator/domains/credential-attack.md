# Credential Attack (Password Spray)

> One-line: load when a target exposes an authentication surface and the program explicitly permits credential testing; yields valid logins that turn into authenticated hunting surface and ATO.

## When to load this
- Program scope/rules **explicitly allow** password spraying / credential attacks (most do NOT — check first).
- Target exposes a real login surface: O365/Azure AD, Okta/other IdP, an OAuth password-grant endpoint, or a custom web login form.
- You have (or can build) a plausible employee/username list and a company-flavored password list.
- **When to spray vs hunt web vulns:** spray when the login is standard/hardened (little web-vuln surface) but the org is large (many users = weak-password odds) and creds are in scope. Hunt web vulns first when the app is custom/feature-rich — a BOLA pays more and carries no lockout risk. Spray is a *surface-opener*, not usually the finding itself.

## Toolchain
Missing tools are skipped, not errors — adapt.
- **`/wordlist-gen` (cewler + hashcat rules)** — crawl the target site, build a company-specific candidate list (SeasonYear!, CompanyName1, etc.).
- **`/breach-check` (HIBP k-anonymity)** — rank candidate passwords by real-world breach frequency; only the first 5 SHA-1 chars leave your machine. Prioritize high-count passwords.
- **`/osint-employees` (theHarvester + username-anarchy)** — derive employee names + the org's email/username format into a user list.
- **`/spray` (TREVORspray for O365/Okta; custom for forms)** — the actual spray, with built-in guards.
- **Burp** — reverse a custom login flow (CSRF token, JS-hashed password, MFA step) before scripting the spray.

## Workflow
1. **Legal gate first — non-negotiable.** Re-read the program's rules for an explicit credential-attack allowance. If absent or ambiguous, **stop** — spraying without written authorization is account-banning and potentially a CFAA-class problem. The `/spray` tool enforces a typed-hostname confirmation; do not bypass it.
2. **Build the user list.** `/osint-employees target.com` → names → apply the org's confirmed email format (`{f}{last}@`, `{first}.{last}@`, etc.). Validate format against any known-good address. Dedup.
3. **Build + rank the password list.** `/wordlist-gen target.com` for company-specific candidates, then `/breach-check list.txt` to rank by breach count. Front-load: `Season+Year!`, `Company@123`, `Welcome1`, plus breach-frequent entries. Keep the list *short* — spray depth is passwords-per-user, and lockout policy caps it.
4. **Pick the mode:**
   - `http-form` — custom web login; script the exact POST (handle CSRF token refresh, client-side hashing, redirect-based success).
   - `oauth` — OAuth 2.0 Resource Owner Password grant endpoint.
   - `o365` — Microsoft 365 / Azure AD (TREVORspray; watch for Smart Lockout).
   - `okta` — Okta org endpoint.
5. **Spray, don't brute.** ONE password across ALL users per round, then wait. Default: 30-min delay between rounds + 60s jitter. Stay strictly under the lockout threshold (typically N-1 attempts per observation window). Brute-forcing one account = lockout + alert = burned engagement.
6. **Rate-limit / lockout tactics.** Learn the policy before spraying at volume (test on one throwaway or the documented policy). Slow-and-low beats fast. Rotate source IPs only if scope permits. O365 Smart Lockout keys partly on IP/behavior — jitter and low volume matter more than raw IP rotation.
7. **Detect success precisely.** Distinguish valid-password-but-MFA (still a win — flags the cred, enables MFA-fatigue/bypass follow-up) from invalid, from locked, from "user doesn't exist." Log every hit with timestamp to the audit trail.

## Evidence bar
- A **valid credential** demonstrated by authenticated access (or an unambiguous auth-success signal: token issued, MFA challenge for a *correct* password, distinct success response vs the invalid baseline).
- The impact statement is what the cred *unlocks* — internal app, another user's data, admin panel — not merely "the password is Welcome1".
- A clean audit log: which users, which passwords, timestamps, rounds, showing you stayed under lockout thresholds and in scope.
- Not evidence: "the login accepted a request" without a success/failure differential; a valid cred you never showed grants any access; anything sprayed without documented authorization.

## Feed back into the flow
Plugs into ../SKILL.md Operational Flow phases 4–8:
- **4 MODEL & RANK** — a valid cred re-scopes the engagement: authenticated surface, the user's roles/tenant, and new features now become the ranked target.
- **5 HUNT** — pivot immediately to authenticated hunting (BOLA across the new account, privilege escalation, business logic) — this is the real payout, spray was the door.
- **6 VALIDATE** — confirm the cred grants concrete access before claiming ATO; a login page accepting a POST is not a finding.
- **7 CHAIN** — valid cred → session → BOLA/BFLA → admin; or valid cred + MFA-bypass → full ATO.
- **8 REPORT** — lead with what the account can reach; include the sanitized audit log to show responsible, in-scope testing.

## Pitfalls
- Spraying without explicit written authorization — the single fastest way to get banned or worse. When in doubt, don't.
- Turning a spray into a brute-force against one account and tripping lockout — always horizontal (one password, all users), never vertical.
- A long password list per round: it *is* brute-forcing across the window and will lock accounts. Keep it short and breach-ranked.
- Ignoring lockout policy and locking out real employees — operationally hostile and reportable against you.
- Reporting the valid password as the finding without demonstrating impact — triagers want what it unlocks.
- Forgetting client-side password hashing / rotating CSRF tokens on custom forms, so every attempt silently fails.
- Not logging attempts — you lose coverage and can't prove you stayed in bounds.
