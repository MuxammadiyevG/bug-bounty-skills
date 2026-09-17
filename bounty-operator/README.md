# bounty-operator

An **engagement brain** skill for authorized bug bounty, pentest, and CTF work. It governs *how* an
AI agent hunts — scope enforcement, intelligence-driven recon, system modeling, authorization-first
prioritization, false-positive gating, honest severity, chaining, cross-session coverage, and
triager-ready reporting. It deliberately ships **no payload arsenal**; per-class depth is routed to
specialist skills you install alongside it.

> **Authorized testing only.** Use only on assets in an active bug-bounty program, a contracted
> pentest, a CTF, or systems you own. The skill enforces scope before any request (Rule 0). Never
> test systems you don't have explicit permission to test.

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
├── SKILL.md                       # always-loaded brain: rules, flow, discipline (~230 lines)
├── references/                    # deep guidance, read on trigger (progressive disclosure)
│   ├── recon-playbook.md          #   recon as intelligence op; when to stop each layer
│   ├── system-modeling.md         #   model auth/roles/tenants/state before attacking
│   ├── high-value-classes.md      #   authorization-first priority + technique radar (refresh)
│   ├── validation-gate.md         #   7-Question Gate, evidence bars, severity anchoring
│   ├── chaining.md                #   low → critical escalation ladders
│   ├── coverage-and-memory.md     #   ledger format + resume + stuck loop
│   ├── reporting.md               #   impact-first templates, platform notes, evidence hygiene
│   ├── per-class-index.md         #   routes each class to specialist + extended scenarios
│   ├── extended-scenarios.md      #   APK/binary/firmware/CTF/malware/JS/.NET routing
│   └── nuclei-workflow.md         #   nuclei as map: templates, usage, custom writing
├── scripts/                       # deterministic discipline tools (no network, no exploits)
│   ├── scope_check.py             #   is this host/URL in scope? (fail-closed)
│   └── ledger.py                  #   coverage ledger: never re-test, never skip, resume
└── README.md                      # install, structure, design notes
```

## Companion specialist skills

`references/per-class-index.md` routes to per-class skills (recon, IDOR/BOLA, GraphQL, SQLi, PII,
WebSocket, dependency-confusion, JS analysis, unauth-recon, triage, chaining) and extended scenarios
(APK/binary/firmware/CTF/malware/.NET/JS encryption via `reverse-skill`). Install the ones you use;
adjust the routing table to whatever names you installed.

Recommended companions:
- **Per-class depth:** your 11 specialist skills (graphunt, sql-sk, idor-claude, pii-hunter, etc.)
- **Extended scenarios:** `zhaoxuya520/reverse-skill` (APK, binary, firmware, CTF, malware, .NET)
- **Automated scanning:** `projectdiscovery/nuclei-templates` + `emadshanab/Nuclei-Templates-Collection`
- **Payload sources:** PayloadsAllTheThings, SecLists, PortSwigger Web Security Academy

## Design notes

- SKILL.md is kept concise; detail lives one level deep in `references/` (progressive disclosure).
- The "technique radar" in `high-value-classes.md` is time-sensitive — refresh it against the current
  OWASP API Top 10, PortSwigger's annual Top 10 web hacking techniques, and recent disclosed reports.
- Built to sit *on top of* payload-heavy specialist skills, not to replace them.

MIT-style use; third-party methodologies referenced keep their own licences. For authorized security
testing only.
