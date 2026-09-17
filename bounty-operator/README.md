# bounty-operator

A **self-contained engagement skill base** for authorized bug bounty, pentest, and CTF work. It
governs *how* an AI agent hunts — scope enforcement, intelligence-driven recon, system modeling,
authorization-first prioritization, false-positive gating, honest severity, chaining, cross-session
coverage, triager-ready reporting — **and** carries the depth in-repo: per-class knowledge, payload
arsenals, bypass tables, disclosed-report patterns, enterprise matrices, and extended domains
(web3, mobile, reverse engineering, CI/CD, credential attack, malware, CTF). No external skills required.

> **Authorized testing only.** Use only on assets in an active bug-bounty program, a contracted
> pentest, a CTF, or systems you own. The skill enforces scope before any request (Rule 0). Never
> test systems you don't have explicit permission to test.

## Design in one line

**Lean brain, deep on demand.** `SKILL.md` (~290 lines) is always loaded; everything else lives one
or more levels deep and is read only when the target needs it (progressive disclosure). A web hunt
never loads the malware or firmware content; the RE toolchain loads only when you reverse a binary.
Self-contained does not mean one giant file.

## Install

Drop the folder into your agent's skills directory:

```
git clone <your-repo> ~/.claude/skills/bounty-operator      # or copy the unzipped folder there
# cross-runtime agents also read ~/.agents/skills/
```

It auto-activates when a session looks like security work (you mention a program, a pentest, a vuln
class, paste HTTP traffic, or ask to recon/validate/report). Give it a **target + scope** and let it
run the Operational Flow.

## Structure

```
bounty-operator/
├── SKILL.md                       # always-loaded brain: rules, flow, discipline (~290 lines)
├── references/                    # workflow depth, read on trigger (progressive disclosure)
│   ├── recon-playbook.md          #   recon as intelligence op; when to stop each layer
│   ├── system-modeling.md         #   model auth/roles/tenants/state before attacking
│   ├── high-value-classes.md      #   authorization-first priority + technique radar (refresh)
│   ├── validation-gate.md         #   7-Question Gate, evidence bars, severity anchoring
│   ├── chaining.md                #   low → critical escalation ladders
│   ├── coverage-and-memory.md     #   ledger format + resume + stuck loop
│   ├── reporting.md               #   impact-first templates, platform notes, evidence hygiene
│   ├── per-class-index.md         #   routes each class to the LOCAL knowledge base
│   ├── extended-scenarios.md      #   routes non-web scenarios to the LOCAL domains/ playbooks
│   └── nuclei-workflow.md         #   nuclei as map: templates, usage, custom writing
├── knowledge/                     # in-repo per-class depth (see knowledge/README.md)
│   ├── vuln-classes/              #   24 web2 classes: root-cause → detect → evidence → ladder → chain → paid example
│   ├── payloads/                  #   per-class payload arsenals by depth tier
│   ├── bypass-tables.md           #   SSRF-IP / open-redirect / upload / 403 / WAF bypasses
│   ├── disclosed-patterns.md      #   recurring patterns distilled from disclosed reports
│   └── enterprise-matrices.md     #   M365 / Okta / vCenter / SSL-VPN attack matrices
├── domains/                       # extended (non-web) playbooks, loaded independently
│   ├── web3-audit.md              #   smart-contract + token/meme rug audit (EVM + Solana)
│   ├── mobile.md                  #   APK/IPA runtime-first pentest
│   ├── credential-attack.md       #   password spray pipeline + guardrails
│   ├── cicd-security.md           #   GH Actions injection, secret exfil, runner poisoning
│   ├── reverse-engineering.md     #   APK/binary/firmware/.NET/JS deobfuscation routing
│   ├── malware-analysis.md        #   defensive triage / IOC / YARA (isolated env only)
│   └── ctf.md                     #   category playbooks (pwn/rev/web/crypto/forensics)
├── scripts/                       # deterministic discipline tools (no exploit firing)
│   ├── scope_check.py             #   is this host/URL in scope? (fail-closed)
│   ├── ledger.py                  #   coverage ledger: never re-test, never skip, resume
│   ├── recon_wrap.py              #   scope-gated recon orchestration (subfinder/httpx/gau/nuclei)
│   ├── chain_helper.py            #   suggest escalation chains from a finding class (offline)
│   └── token_scanner.py           #   offline rug/red-flag heuristics for token contracts (EVM + Solana)
└── README.md                      # this file
```

## What it is NOT

The engagement brain first, with the arsenal attached — **not a blind auto-exploiter**. It carries
payloads, but the brain governs their use: every payload rides a hypothesis, every finding meets its
evidence bar, severity stays honest. It fires no exploit blindly, never bulk-exfiltrates (prove with
one record, then stop), refuses unauthorized targets, and never fabricates findings.

## Design notes

- SKILL.md is kept concise; detail lives in `references/`, `knowledge/`, and `domains/` (progressive disclosure).
- The "technique radar" in `high-value-classes.md` is time-sensitive — refresh it against the current
  OWASP API Top 10, PortSwigger's annual Top 10 web hacking techniques, and recent disclosed reports.
- Content is original synthesis under MIT. Payloads are standard open-source primitives
  (PayloadsAllTheThings / PortSwigger Web Security Academy style); refresh them against current sources.
- Optional external deep-dive skills (e.g. `zhaoxuya520/reverse-skill`) can sit alongside; the
  `domains/` files note where to defer to them, but stand on their own.

MIT-style use; third-party methodologies referenced keep their own licences. For authorized security
testing only.
