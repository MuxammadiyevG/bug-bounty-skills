# Per-Class Index — route to the local knowledge base for depth

> bounty-operator is self-contained. It carries the engagement brain **and** the per-class depth.
> When a specific vulnerability class becomes the objective, open its file in `knowledge/vuln-classes/`
> and follow the deep technique — then bring the result back through the Validation Gate and the ledger.
> Nothing here depends on an external skill.

## How to use this file

1. First model the system (`system-modeling.md`) and rank classes by value (`high-value-classes.md`).
2. In the HUNT phase, once you commit to a class, open its `knowledge/vuln-classes/<class>.md` file
   **before** improvising — read-then-hunt, not hunt-then-guess.
3. Do the deep, class-specific work: root cause, where it hides, detection, evidence bar, depth ladder.
   Pull payloads from the matching `knowledge/payloads/<class>.md` arsenal.
4. Return here: validate (`validation-gate.md`), chain (`chaining.md`), log with `scripts/ledger.py`.

## Routing table — class → local knowledge file

| Objective / class | Open this file |
|---|---|
| IDOR / BOLA / BFLA / BOPLA / cross-tenant authz | `knowledge/vuln-classes/idor-bola.md` |
| SSRF (incl. blind/OOB) | `knowledge/vuln-classes/ssrf.md` |
| Cloud metadata / infra misconfig / exposed buckets | `knowledge/vuln-classes/ssrf-cloud.md` |
| XSS (reflected/stored/DOM/mutation) | `knowledge/vuln-classes/xss.md` |
| SQL injection | `knowledge/vuln-classes/sqli.md` |
| NoSQL injection | `knowledge/vuln-classes/nosqli.md` |
| Command injection | `knowledge/vuln-classes/command-injection.md` |
| LFI / file inclusion → RCE | `knowledge/vuln-classes/lfi-rce.md` |
| Insecure deserialization | `knowledge/vuln-classes/deserialization.md` |
| Auth bypass / session / JWT / ATO | `knowledge/vuln-classes/auth-bypass.md` |
| OAuth / OIDC flow attacks | `knowledge/vuln-classes/oauth-oidc.md` |
| MFA / 2FA bypass | `knowledge/vuln-classes/mfa-bypass.md` |
| SAML attacks (XSW, comment injection, sig stripping) | `knowledge/vuln-classes/saml-attacks.md` |
| Business-logic / sensitive-flow abuse | `knowledge/vuln-classes/business-logic.md` |
| Race conditions / TOCTOU | `knowledge/vuln-classes/race-conditions.md` |
| File upload → RCE / stored payload | `knowledge/vuln-classes/file-upload.md` |
| GraphQL (introspection, batching, aliasing IDOR, authz) | `knowledge/vuln-classes/graphql.md` |
| SSTI (Jinja2/Twig/Freemarker/ERB/Spring) | `knowledge/vuln-classes/ssti.md` |
| XXE | `knowledge/vuln-classes/xxe.md` |
| API misconfig (mass assignment, JWT, prototype pollution, CORS) | `knowledge/vuln-classes/api-misconfig.md` |
| HTTP request smuggling (CL.TE/TE.CL/H2.CL) | `knowledge/vuln-classes/http-smuggling.md` |
| Web cache poisoning / deception | `knowledge/vuln-classes/cache-poisoning.md` |
| Subdomain takeover | `knowledge/vuln-classes/subdomain-takeover.md` |
| LLM / AI security (prompt injection, chatbot IDOR, ASI01-10) | `knowledge/vuln-classes/llm-ai.md` |

## Cross-cutting knowledge

| Need | Open this file |
|---|---|
| Payload arsenals per class (depth ladders) | `knowledge/payloads/<class>.md` |
| SSRF-IP / open-redirect / upload / 403 / WAF bypass tables | `knowledge/bypass-tables.md` |
| Recurring patterns distilled from disclosed reports | `knowledge/disclosed-patterns.md` |
| M365 / Okta / vCenter / SSL-VPN attack matrices | `knowledge/enterprise-matrices.md` |
| **Non-web domains** (mobile, web3, RE, CI/CD, malware, CTF, credential) | **See `extended-scenarios.md`** |
| **Automated scanning** | **See `nuclei-workflow.md`** |

## Extended domains → `domains/`

| Domain | Open this file |
|---|---|
| Mobile pentest (APK / IPA, runtime-first) | `domains/mobile.md` |
| Smart-contract / web3 / token audit | `domains/web3-audit.md` |
| Password spray / credential attack | `domains/credential-attack.md` |
| CI/CD pipeline security | `domains/cicd-security.md` |
| Reverse engineering (APK/binary/firmware/.NET/JS) | `domains/reverse-engineering.md` |
| Malware analysis (defensive) | `domains/malware-analysis.md` |
| CTF challenges | `domains/ctf.md` |

## When a class has no dedicated file yet

1. Research the *current-year* technique for the exact stack/framework you fingerprinted.
2. Pull the full payload set from `knowledge/payloads/` or a reputable public source (PayloadsAllTheThings,
   PortSwigger Web Security Academy) rather than improvising from memory — one probe proves nothing.
3. Climb the full depth ladder for the class before concluding it's clean.
4. Still route the result through the Validation Gate, chain filter, and ledger.

## Depth ladders (don't stop at payload #5)

- **SQLi:** error → boolean-blind → time-blind → UNION → stacked → OOB → second-order → WAF-bypass
- **XSS:** reflected → stored → DOM → filter/encoder bypass → CSP bypass → mutation XSS
- **SSRF:** basic → blind (OOB) → protocol smuggling → cloud metadata → internal service pivot
- **IDOR:** horizontal read → vertical/BFLA → sub-route skip → predictable-id enumeration → write IDOR
- **Auth:** password reset flaws → session fixation → JWT abuse → MFA bypass → OAuth/SSO flow abuse

Exhausting the ladder — not spraying five payloads — is what separates a confirmed-clean surface
from a missed critical.
