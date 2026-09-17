# Disclosed-Report Patterns

Recurring shapes distilled from public bug-bounty disclosures. Each entry: the **pattern** (the structural mistake) and the **tell** (what in recon/traffic reveals it). Patterns are generalized — no specific report is cited. Read this to know *where to look* before you start firing payloads.

---

## IDOR / BOLA

- **Sequential id in an API you don't own the object in.** Tell: numeric ids in URLs/bodies that increment 1-by-1 across your own actions; a `GET /resource/{id}` that never varies its response shape by owner.
- **Authorization enforced on the UI route but not the API.** Tell: the SPA hides a button, but the underlying `/api/...` call has no owner check. Diff what the frontend gates vs what the backend enforces.
- **UUID leaked, then replayed.** Tell: a random object id appears in a list/search/`?include=`/email/referer belonging to another user; the sensitive endpoint accepts it without a second check.
- **Object id in an unexpected slot.** Tell: id in a cookie, header (`X-Account-Id`), or JWT claim that the server trusts blindly. Swap it.
- **Export/report/print endpoints skip the check.** Tell: `/invoice/{id}/pdf`, `/export?id=`, `/print` — the "secondary" path is written by a different dev and forgotten.
- **Mass assignment on update.** Tell: PATCH/PUT accepts more fields than the form shows; add `owner_id`, `role`, `is_admin`, `tenant_id`.

## SSRF

- **URL-fetch feature with a naive allowlist.** Tell: webhook config, "import from URL", link-preview, avatar-by-URL, PDF/screenshot renderer. Allowlist checked on the *first* URL only → redirect-bounce or DNS-rebind.
- **Metadata reachable from a fetcher on a cloud host.** Tell: the app runs on AWS/GCP/Azure (check response headers, IP ranges, `Server`), and a fetch param exists. IMDSv1 still enabled is common.
- **PDF/HTML renderer with SSRF via embedded resource.** Tell: user-supplied HTML/markdown/SVG rendered server-side; inject `<img src=http://169.254.169.254/...>` or an iframe.
- **Blind SSRF in an analytics/webhook pipeline.** Tell: a callback fires seconds later; no reflection. Confirm with OOB.

## Auth / session / OAuth

- **Password reset token leaks in the response or is guessable.** Tell: reset endpoint returns the token in JSON, or the token is a short/sequential/timestamp value.
- **Host-header poisoning of reset links.** Tell: reset email link's domain follows the `Host`/`X-Forwarded-Host` you send → send victim a link pointing at your server, catch their token.
- **OAuth `redirect_uri` too permissive.** Tell: redirect_uri validated by prefix/substring, or an open redirect exists on an allowed host → chain to steal the `code`/token. `state` missing → CSRF the linking flow.
- **JWT: alg confusion / none / weak secret.** Tell: `alg:HS256` with a public RSA key reusable as HMAC secret; `alg:none` accepted; short signing secret crackable.
- **MFA gate applied at UI, not at the token-issuing API.** Tell: the `/verify-otp` step returns a session even when skipped, or the pre-MFA token already grants access to sensitive endpoints.
- **Account merge / email-change without re-verification.** Tell: change-email endpoint updates immediately; login-with-social links to any existing account by email.
- **Session not rotated on privilege change / logout doesn't invalidate server-side.** Tell: old cookie still works after password change.

## Business logic

- **Negative / overflow quantity or price.** Tell: cart/transfer accepts `-1` quantity, huge values, or fractional cents → credit yourself or pay negative.
- **Coupon / referral reuse.** Tell: single-use code accepted twice via race or re-POST; self-referral credited.
- **State-machine skip.** Tell: you can hit step 3's endpoint without completing step 1/2 (payment, KYC, approval). Forge the "completed" state param.
- **Currency / rounding mismatch.** Tell: price computed client-side and trusted, or currency swapped between quote and charge.
- **Race condition on a limited resource.** Tell: balance/withdrawal/vote/redeem check-then-act with no lock → fire N parallel requests, double-spend.
- **Trial / tier bypass via param.** Tell: `plan=free` in a body you can flip to `enterprise`; feature flag in client JS.

## Injection & file

- **Second-order injection through a "safe" stored field.** Tell: username/display-name/filename stored raw, later concatenated into a query, template, or shell in an admin/report job.
- **SSTI in a "personalization" feature.** Tell: email templates, invoice notes, custom greetings that echo your input transformed (name uppercased ≠ template eval; `{{7*7}}`=49 does).
- **LFI/traversal in a download/theme/lang param.** Tell: `?file=`, `?template=`, `?lang=` whose value maps to a filesystem path; `.` or `/` changes the response.
- **File upload → RCE via config file or double extension.** Tell: upload dir is web-served; extension check is blacklist-based; `.htaccess`/`web.config` accepted.
- **XXE in an XML/SAML/Office-import endpoint.** Tell: `Content-Type: application/xml`, SAML SSO, or docx/xlsx import; flip a JSON API to XML and see if it parses.

## API & GraphQL

- **Introspection left on in production.** Tell: `/graphql` answers `__schema` queries → full type map, hidden mutations. Even with introspection off, field-suggestion errors ("did you mean...") leak names (clairvoyance).
- **Aliasing defeats rate limits / enables IDOR batch.** Tell: one GraphQL doc with N aliased calls (`a: user(id:1) b: user(id:2)`) runs unthrottled → brute OTP/ids in a single request.
- **Mutation with no authz on a field the query gates.** Tell: read is protected but `updateUser`/`deleteX` mutation isn't; the resolver trusts the client.
- **Verb/route drift between REST and GraphQL for the same object.** Tell: object locked in REST, reachable via a GraphQL resolver (or vice versa).
- **Pagination / filter over-fetch.** Tell: `first: 100000` or a `filter` that accepts fields the UI never sends, returning other tenants' rows.

## Cache & headers

- **Web cache poisoning via unkeyed input.** Tell: an unkeyed header (`X-Forwarded-Host`, `X-Forwarded-Scheme`) reflected into a cached response → poison a shared page for all users.
- **Cache deception.** Tell: `/account/profile.css` (fake static extension) served the authenticated page and cached it publicly.
- **Sensitive response cached.** Tell: `Cache-Control` missing/`public` on an authenticated endpoint; CDN caches PII.

## Access control / infra

- **Debug/actuator/admin endpoint left public.** Tell: `/actuator/env`, `/debug`, `/.git/`, `/swagger`, `/graphql` introspection on, verbose stack traces. Recon dir-fuzz hits these.
- **Subdomain takeover.** Tell: a CNAME points at a deprovisioned SaaS (S3/Heroku/GitHub Pages/Azure) returning the provider's "no such bucket/app" page.
- **CORS with reflected origin + credentials.** Tell: `Access-Control-Allow-Origin` echoes your `Origin` and `Allow-Credentials: true` → read authenticated responses cross-site.
- **Secrets in JS bundles / source maps / git.** Tell: `.map` files served, API keys in frontend JS, `.git/config` reachable.
- **Cloud storage misconfig.** Tell: `s3.amazonaws.com`/`storage.googleapis.com`/`blob.core.windows.net` URLs in responses; buckets listable or writable; predictable bucket names from the org name.
- **Internal CI/CD or artifact endpoints exposed.** Tell: reachable Jenkins/GitLab/Argo, unauthenticated build logs leaking tokens, public GitHub Actions workflow injectable via PR title/branch name.

## File upload & rendering

- **Uploaded file served from the app origin.** Tell: avatar/attachment URL is same-origin and preserves your extension → stored XSS (SVG/HTML) or RCE (php/jsp).
- **Server-side image/office processing.** Tell: ImageMagick/Ghostscript/LibreOffice in the pipeline → known coder CVEs, SSRF via MSL/SVG, or command injection through crafted files.
- **Filename reflected without sanitization.** Tell: `Content-Disposition` echoes your filename → header/CRLF injection or download-name XSS.

## Race conditions & timing

- **Check-then-act with no lock on money/limits.** Tell: balance, coupon, invite, vote, or withdrawal endpoints; fire parallel requests to cross the limit once.
- **TOCTOU on state validation.** Tell: a resource validated then used in two steps; flip it between the two.
- **Login/OTP timing side-channel.** Tell: measurable response-time delta between valid and invalid usernames or partial OTP matches.

## The meta-tell
Most paid bugs come from a **seam**: two components (UI vs API, front-end vs origin, v1 vs v2, first URL vs redirect, quote vs charge, check vs act) that disagree about who enforces the rule. When you find a boundary where one side assumes the other validated, dig there.
