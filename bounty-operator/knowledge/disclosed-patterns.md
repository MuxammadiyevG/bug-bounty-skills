# Disclosed-Report Patterns — real HackerOne cases, distilled

> Every entry below is a **real, publicly disclosed HackerOne report** — exact title, program, and
> bounty as listed in the community-curated `reddelexc/hackerone-reports` top-lists
> (`docs/tops_by_bug_type/`), corroborated against the source rows. Fetched 2026-09-17. Titles and
> IDs are verbatim; a `$0`/blank source bounty is shown as **bounty undisclosed** (the report is
> public but the amount was never published), never as "$0 paid". Verify any entry at
> `hackerone.com/reports/<id>`.
>
> Use this file two ways: (1) before hunting a class, read its **TELL** — the recurring shape that
> reveals the bug across real paid cases; (2) after *you* land a finding, add it back here (title,
> program, bounty, the tell) so the base compounds. The tell is the reusable asset — not the payload.

---

## Authorization & account

### IDOR / BOLA / BFLA / BOPLA
- IDOR to add secondary users in paypal.com/businessmanage/users/api/v1/users — PayPal — **$10,500** — /reports/415081
- An IDOR leading to enumeration + email/phone disclosure in cashier — Unikrn — **$3,000** — /reports/1966006
- idor allows you to delete photos and album from a gallery — Pornhub — **$1,500** — /reports/380410
- [Razer Pay] Broken access control allowing other user's bank account deletion — Razer — **$1,000** — /reports/757095
- IDOR allow access to payments data of any user — Nord Security — bounty undisclosed — /reports/751577

**TELL:** session is authenticated but the object id in the path/body is never re-checked for ownership. Top payouts are the **write/delete** variants (add user, delete bank account, edit others' media), not read-only leaks. UUIDs hide enumeration but do not enforce access — still test them.

### Authentication bypass & session
- Account Takeover via Password Reset without user interaction — GitLab — **$35,000** — /reports/2293343
- Account takeover via leaked session cookie — HackerOne — **$20,000** — /reports/745324
- Potential pre-auth RCE on Twitter VPN — X / xAI — **$20,160** — /reports/591295
- Spring Actuator endpoints public + broken auth — LY Corporation — **$12,500** — /reports/838635
- Login as any user with otp/logout & otp/login — Snapchat — bounty undisclosed — /reports/921780

**TELL:** a later step trusts that an earlier step already proved identity — reset token not bound to the account, session cookie replayed, re-auth gate never re-checked. Each is a step that should re-verify and doesn't, landing directly on ATO.

### MFA / 2FA bypass
- Bypass 2FA + reporter blacklist through embedded submission form — HackerOne — **$10,000** — /reports/418767
- TikTok 2FA Bypass — TikTok — **$1,564** — /reports/1247108
- 2FA bypass by sending blank code — Glassdoor — bounty undisclosed — /reports/897385
- Sessions created before MFA activation stay valid — Superhuman — bounty undisclosed — /reports/667739
- Password not checked when disabling 2FA — HackerOne — bounty undisclosed — /reports/587910

**TELL:** MFA is enforced on exactly one code path. Flip to an alternate endpoint, an embedded form, a stale pre-existing session, or a blank/unchecked code and the second factor is never actually verified server-side.

### Business-logic / sensitive-flow abuse
- Project Template copies private repo/issues/snippets/MRs — GitLab — **$12,000** — /reports/689314
- ATO via Email ID change + Forgot Password ordering — New Relic — **$2,048** — /reports/1089467
- OLO total-price manipulation using negative quantities — Upserve — bounty undisclosed — /reports/364843
- "Report as abuse" abused to delete any user's post — Vanilla — **$300** — /reports/411075

**TELL:** no injection, no broken token — the feature runs exactly as coded, but a client-trusted value (negative qty), a flow ordering (email change → reset), or a workflow trigger (report-as-abuse, template copy) reaches a state the developer assumed unreachable.

### Race conditions / TOCTOU
- Race condition bypasses a verification check — Tools for Humanity — **$3,000** — /reports/2110030
- Race in email activation → infinite diamonds — InnoGames — **$2,000** — /reports/509629
- Redeem gift cards multiple times → free money — Reverb — bounty undisclosed — /reports/759247
- Bypassing HackerOne 2FA due to race condition — HackerOne — bounty undisclosed — /reports/2598548

**TELL:** a "happens once" guard (redeem/activate/verify/pay once) sits on a non-atomic check-then-act; N parallel requests into the check-to-commit window make the limit hold zero times.

---

## Server-side & code execution

### SSRF (generic / blind)
- SSRF via Analytics Reports — HackerOne — **$25,000** — /reports/2262382
- Full-response SSRF via Google Drive — Dropbox — **$17,576** — /reports/1406938
- SSRF on project import via remote_attachment_url — GitLab — **$10,000** — /reports/826361
- Blind SSRF to internal services in matrix preview_link API — Reddit — **$6,000** — /reports/1960765
- SSRF mitigation bypass — GitLab — bounty undisclosed — /reports/632101

**TELL:** a feature built to fetch a URL you supply (import-from-URL, link preview, report/PDF generator) with no egress allow-list, or a filter bypassable via DNS re-resolution / redirect. Prove blind cases with an OOB callback — a hung request is not proof.

### SSRF → cloud metadata / creds
- SSRF at hellosign.com → AWS private keys — Dropbox — **$4,913** — /reports/923132
- SSRF via JavaScript exfils Google metadata — Snapchat — bounty undisclosed — /reports/530974
- SSRF via upload leaks GCP SSH keys — Vimeo — bounty undisclosed — /reports/549882
- Full-read SSRF leaks AWS metadata + LFI — Evernote — bounty undisclosed — /reports/1189367
- SSRF in Exchange → ROOT on all instances — Shopify — bounty undisclosed — /reports/341876

**TELL:** server-side fetch (upload/PDF/preview/import) pointed at the link-local metadata IP (169.254.169.254 / metadata.google.internal); response returns role creds or SSH keys. This is the archetypal chain root.

### Command injection (OS / argument)
- RCE removing metadata with ExifTool — GitLab — **$20,000** — /reports/1154542
- Git flag injection → local file overwrite → RCE — GitLab — **$12,000** — /reports/658013

**TELL:** user input reaches a CLI call (converter, metadata stripper, git) — shell metacharacters break out, or a bare value is parsed as a flag (argument injection, no metacharacter needed). *Disclosed clean OS-command cases are rarer than the class's reputation — most "RCE" tops are upload/deser/dep-confusion.*

### LFI / file read → RCE
- Path traversal → RCE — GitLab — **$12,000** — /reports/733072
- Mozilla VPN client: RCE via file write + path traversal — Mozilla — **$6,000** — /reports/2995025
- Keybase: write files anywhere in userland via relative path — Keybase — **$5,000** — /reports/713006
- Path traversal + SSTI + RCE on a Mail.ru acquisition — Mail.ru — **$2,000** — /reports/536130
- HTML-injection in PDF-export → LFI — Visma — **$500** — /reports/809819

**TELL:** input maps to a filesystem path with no canonicalization — traversal (`../`, encoded, absolute) proves the read; a wrapper/log/template/write sink turns read into execution.

### Insecure deserialization
- RCE via ActiveSupport::MessageVerifier/MessageEncryptor — Ruby on Rails — **$1,500** — /reports/473888
- Java deser RCE via JBoss JMXInvokerServlet — Starbucks — bounty undisclosed — /reports/153026
- Bundler RCE via Marshal — RubyGems — bounty undisclosed — /reports/1119120
- Telerik UI deser RCE (CVE-2019-18935) — U.S. DoD — bounty undisclosed — /reports/1174185

**TELL:** a serialized blob crossing a trust boundary — Java `rO0` token, Ruby Marshal string, .NET/Telerik viewstate, signed cookie with a leaked secret — deserialized into live objects that fire gadget chains at load time. *High-bounty deser cases skew low/undisclosed in this dataset.*

### File upload → RCE / stored payload
- Unrestricted file upload on ambassador.mail.ru — Mail.ru — **$3,000** — /reports/854032
- External SSRF + local file read via video upload (FFmpeg HLS) — TikTok — **$2,727** — /reports/1062888
- Blind XSS on image upload — CS Money — **$1,000** — /reports/1010466
- Webshell via file upload — Starbucks — bounty undisclosed — /reports/506646

**TELL:** server validates the wrong thing (client-side, Content-Type, extension) or hands the file to a parser — the file lands in a web-executed path as a shell, or the parser (FFmpeg, image lib) fetches/reads on your behalf.

---

## Injection & client-side

### XSS
- Bypass of #488147 re-enables stored XSS on paypal.com/signin — PayPal — **$20,000** — /reports/510152
- Stored XSS on paypal.com/signin via cache poisoning — PayPal — **$18,900** — /reports/488147
- XSS in Steam react chat client — Valve — **$7,500** — /reports/409850
- Reflected XSS in OAuth2 login flow — LY Corporation — **$1,989** — /reports/697099

**TELL:** top payouts put execution on an authenticated, session-bearing origin — login/OAuth pages and stored/persistent sinks — and often re-break a patched bug (510152 bypasses 488147). Reflected `alert(1)` on marketing pages pays ~nothing. Must *execute*, not just reflect.

### SQLi
- SQLi in report_xml.php via countryFilter[] — Valve — **$25,000** — /reports/383127
- Time-based SQLi at city-mobil.ru — Mail.ru — **$15,000** — /reports/868436
- SQLi at fleet.city-mobil.ru — Mail.ru — **$10,000** — /reports/881901
- Blind SQLi at windows10.hi-tech.mail.ru — Mail.ru — **$5,000** — /reports/786044
- SQLi → RCE at contact-sys.com — QIWI — bounty undisclosed — /reports/816254

**TELL:** filter/report/sort params and legacy secondary apps, proven by boolean/time differential. Escalation to RCE (QIWI) or full-DB read multiplies the reward. Never dump real user data — prove and stop.

### NoSQLi (scarce in public H1)
- Closest analog: SQLi via countryFilter[] bracket param — Valve — **$25,000** — /reports/383127
- Closest analog: injection-into-query-structure → RCE — QIWI — bounty undisclosed — /reports/816254

**TELL:** paid, disclosed NoSQL/MongoDB injection does **not** appear in the H1 top-lists — it is genuinely rare in public data; the tops are all relational SQLi. Mechanically identical tell: user input reaching the query as *structure* (`param[$ne]=`, `$where` eval), not as a bound value.

### SSTI
- [Ruby] Server-side template injection — GitHub Security Lab — **$2,300** — /reports/1928279
- Path traversal + SSTI + RCE on a Mail.ru acquisition — Mail.ru — **$2,000** — /reports/536130
- SSTI in Return Magic email templates — Shopify — bounty undisclosed — /reports/423541
- SSTI via Smarty template → RCE — Unikrn — bounty undisclosed — /reports/164224

**TELL:** sink is a user-customizable template field (email templates especially); prove server-side evaluation (`{{7*7}}`→49), then walk the engine object model to RCE. *Many top SSTI rows are $0 CodeQL/query reports, so bounty-bearing cases skew lower than XSS/SQLi.*

### XXE
- XXE on pulse.mail.ru — Mail.ru — **$6,000** — /reports/505947
- Multiple endpoints vulnerable to XXE — Pornhub — **$2,500** — /reports/72272
- XXE at ecjobs.starbucks.com.cn (.aspx handler) — Starbucks — bounty undisclosed — /reports/500515
- XXE via SVG upload → SSRF — Zivver — bounty undisclosed — /reports/897244

**TELL:** any endpoint or format that is XML underneath (SOAP, .aspx handlers, SVG/JPEG-XMP uploads) with DTD/external-entity processing on. Impact is file read or SSRF pivot; blind bypasses of prior patches recur.

### Cache poisoning / deception
- DoS on PayPal via web cache poisoning — PayPal — **$9,700** — /reports/622122
- Host-header cache poisoning → DoS — Shopify — **$2,900** — /reports/1096609
- Cache poisoning → stored DOM XSS defacing catalog.data.gov — GSA — **$750** — /reports/303730
- Web cache deception → name/user_id enumeration — OLX — bounty undisclosed — /reports/537564

**TELL:** an input that influences the response but is absent from the cache key (Host / X-Forwarded-Host / fat param). Impact spans mass DoS → stored XSS from cache → cross-user info. Always prove with a cache buster, never on real users.

---

## API, auth-federation & infra

### GraphQL
- DoS via mutation aliasing in account-recovery API — HackerOne — **$12,500** — /reports/3287208
- Unauth RCE in Taskcluster web-server via GraphQL filter (sift `$where`) — Mozilla — **$12,000** — /reports/3782701
- IDOR on GraphQL BillingDocumentDownload / BillDetails — Shopify — **$5,000** — /reports/2207248
- SSRF in GraphQL query — EXNESS — **$3,000** — /reports/1864188

**TELL:** authz is per-resolver, so one field forgets the check; arguments flow straight into backend queries/fetches (injection/SSRF); **aliasing** turns authz gaps and rate limits into scale.

### OAuth / OIDC
- DoS any org's SSO → opens ATO door — Superhuman — **$10,500** — /reports/976603
- Stealing SSO login tokens — Snapchat — **$7,500** — /reports/265943
- Blind SSRF in OAuth Jira authorization controller — GitLab — **$4,000** — /reports/398799
- Bypass email verification for OAuth grants → 3rd-party ATO — GitLab — **$3,000** — /reports/922456
- Steal OAuth code via redirect_uri — pixiv — **$2,000** — /reports/1861974
- redirect_uri bypass via IDN homograph → token leak — Semrush — bounty undisclosed — /reports/861940

**TELL:** the authorization server / relying party trusts something unverified — loosely-matched `redirect_uri`, unverified-email account linking, or an SSO token that leaks cross-origin. The primitive pays only when driven to a captured code/token + a real session.

### API misconfiguration
- API access to Phabricator via leaked cert in git repo — Uber — **$39,999** — /reports/591813
- Exposed Kubernetes API → RCE / exposed creds — Snapchat — **$25,000** — /reports/455645
- Blind SSRF to internal services in preview_link API — Reddit — **$6,000** — /reports/1960765
- Flickr ATO using AWS Cognito API — Flickr — bounty undisclosed — /reports/1342088

**TELL:** the API works "correctly" — the bug is what it *exposes or trusts*. Unauth/leaked-credential surface pays most; reflected origins and client-supplied params (SSRF/CORS/mass-assignment) next.

### HTTP request smuggling
- HTTP request smuggling via HTTP/2 — Basecamp — **$7,500** — /reports/1211724
- Request smuggling on canpol.deti.mail.ru — Mail.ru — **$5,000** — /reports/957881
- Password theft on login.newrelic.com via smuggling — New Relic — **$3,000** — /reports/498052
- Mass ATO via smuggling on slackb.com — Slack — bounty undisclosed — /reports/737140

**TELL:** CDN/proxy and origin disagree on request length (CL.TE / TE.CL / H2.CL); smuggled bytes prepend onto the next connection user's request. Payout tracks to captured sessions/creds and mass 0-click ATO.

### Subdomain takeover
- Takeover via insecure CloudFront cdn.grab.com — Grab — **$1,000** — /reports/352869
- Takeover of storybook.lystit.com — Lyst — **$1,000** — /reports/779442
- Auth bypass on auth.uber.com via takeover of saostatic.uber.com — Uber — bounty undisclosed — /reports/219205
- Takeover → authentication bypass — Roblox — bounty undisclosed — /reports/335330

**TELL:** dangling DNS to a deprovisioned provider resource. On its own it's low; the payout is set by **what trusts the subdomain** — cookie scope, OAuth callback, or SSO/auth host → auth bypass.

### SAML (no top-list; web-sourced)
- SAML authentication bypass on uchat.uberinternal.com — Uber — **$8,500** — /reports/223014
- SAML signature-verification bypass → log in as any user (ruby-saml parser differential, CVE-2025-25291/25292) — GitHub — bounty undisclosed — /reports/2579939
- SAML signup domain-enforcement bypass → unauthorized org access — HackerOne — bounty undisclosed — /reports/2101076

**TELL:** the SP verifies a signature over one element but consumes another — parser differential, XML signature wrapping (XSW), or a domain/claim enforcement miss. Payout = proven cross-user login, not "assertion accepted".

### LLM / AI (new surface, thin public disclosure)
- LLM01: Invisible Prompt Injection (zero-width Unicode tag chars smuggle instructions) — HackerOne — **$2,500** — /reports/2372363
- Copilot Chat prompt injection exfiltrates private source ("CamoLeak", CVE-2025-59145) — GitHub — bounty undisclosed — /reports/2383092
- RCE via prompt injection in Vanna.AI (CVE-2024-5565) — huntr — bounty undisclosed — huntr.com/bounties/90620087-44ac-4e43-b659-3c5d30889369

**TELL:** payment follows a **crossed boundary** — a data-exfil channel, a code-exec tool, or other-user data — not rude/jailbroken output. Public H1 disclosures are still thin; most verified AI/ML cases live on huntr. Jailbreak-only text is not paid. See `vuln-classes/llm-ai.md` for the ASI01–ASI10 frame.

---

## The meta-lesson

Across every class, the paid reports share one shape: **a boundary that one side assumes is checked
and the other side never re-checks** — object ownership, identity between steps, a cache key, a
parser's view of the same bytes, a template's trust of a field, an authorization server's trust of a
redirect. Scanners see requests; the money is in the *disagreement between two components*. Read the
TELL, find the seam, prove impact once, then stop.

**Keep this file alive:** when you confirm a finding, append it here (title / program / bounty / the
tell) and note the pattern in the matching `vuln-classes/<class>.md`. The base is only as current as
its last real case. Refresh the source top-lists periodically at
`github.com/reddelexc/hackerone-reports`.
