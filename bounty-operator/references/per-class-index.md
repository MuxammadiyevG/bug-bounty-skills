# Per-Class Index — route to specialist skills for depth

> bounty-operator is the engagement brain. It deliberately does **not** carry a payload arsenal.
> When a specific vulnerability class becomes the objective, load the matching specialist skill and
> follow its deep technique — then bring the result back through the Validation Gate and the ledger.

## How to use this file

1. First model the system (`system-modeling.md`) and rank classes by value (`high-value-classes.md`).
2. In the HUNT phase, once you commit to a class, open its specialist skill **before** improvising.
3. Do the deep, class-specific work there (detection methodology, per-class evidence, WAF handling).
4. Return here: validate (`validation-gate.md`), chain (`chaining.md`), log with `scripts/ledger.py`.

## Routing table

Map the class to the specialist skill you have installed. Names below match the specialist
collection this operator was built to sit on top of — adjust to whatever you actually installed.

| Objective / class | Load this specialist skill |
|---|---|
| Recon, attack-surface mapping, "just a domain" | `recon-hunter` |
| Unauthenticated P1/P2 from a TLD, exposures, takeovers, pre-auth CVEs | `p1-unauth-recon-agent` |
| JavaScript bundle analysis — secrets, endpoints, tokens | `jsmax` |
| IDOR / BOLA / BFLA / cross-tenant authorization | `idor-claude` |
| GraphQL (introspection, batching, nested authz, DoS) | `graphunt` |
| SQL / NoSQL injection (web, API, mobile) | `sqli-hunter-agent` |
| PII / mass-data exposure, GDPR-reportable leaks | `pii-hunter` |
| WebSocket vulnerability classes | `websocket-skill` |
| Dependency confusion / package substitution (npm, cargo) | `dependency-confusion` |
| Standalone triage/validation deep dive | `triage-validation` |
| Chaining strategy deep dive | `bug-chaining` |
| **Extended scenarios (non-web)** | **See `extended-scenarios.md`** |
| APK / Android reverse → API surface extraction | `reverse-skill` → `apk-reverse/` |
| iOS / mobile app analysis | `reverse-skill` → `mobile-reverse/` |
| Binary RE (exe/dll/so/elf) | `reverse-skill` → `ida-reverse/` or `radare2/` |
| .NET / C# reverse engineering | `reverse-skill` → `dotnet-reverse/` |
| Frontend JS / encrypted request params | `reverse-skill` → `js-reverse/` |
| Firmware / IoT | `reverse-skill` → `firmware-pentest/` |
| CTF challenges (42 sub-skills) | `reverse-skill` → `CTF-Sandbox-Orchestrator/` |
| Malware / YARA analysis | `reverse-skill` → `malware-analysis/` |
| Attack chain / red-team orchestration | `reverse-skill` → `attack-chain/` |
| API / GraphQL (extended) | `reverse-skill` → `api-security/` |
| Supply chain / SBOM | `reverse-skill` → `supply-chain-security/` |
| LLM / AI security | `reverse-skill` → `llm-security/` |
| **Automated scanning** | **See `nuclei-workflow.md`** |
| Nuclei: tech-targeted CVE + misconfig sweep | `nuclei` + `projectdiscovery/nuclei-templates` |
| Nuclei: fuzzing params/headers | `nuclei` + `projectdiscovery/fuzzing-templates` |
| Nuclei: community templates (300+ repos) | `emadshanab/Nuclei-Templates-Collection` |

## When no specialist exists for the class

If you hit a class with no installed specialist (e.g. request smuggling, SSTI, deserialization,
SAML, cache poisoning):

1. Research the *current-year* technique for the exact stack/framework you fingerprinted.
2. Pull the full payload set from a reputable public source (PayloadsAllTheThings, PortSwigger Web
   Security Academy) rather than improvising from memory — one probe proves nothing.
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
