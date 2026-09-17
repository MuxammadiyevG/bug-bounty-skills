# bounty-operator — Self-Contained Mega Skill Base (Design)

**Date:** 2026-09-17
**Status:** Approved (Option A — self-contained monorepo, lean brain + progressive depth)
**Author:** mikro + Claude

## 1. Goal

Turn `bounty-operator` from a payload-free *brain that routes to external companion
skills* into a **single self-contained skill base** that needs no external skills — while
keeping the lean, progressive-disclosure architecture that made it good.

One repo holds: the engagement brain (behavior/workflow), full per-class web knowledge +
payloads, enterprise/disclosed-pattern knowledge, and every extended domain (web3, mobile,
credential-attack, CI/CD, reverse engineering, malware, CTF) — each loaded only on trigger.

## 2. Non-Goals

- **No literal 5000-line SKILL.md.** SKILL.md stays lean (~280 lines), always-loaded.
  Depth lives one+ level deep, read on trigger (progressive disclosure).
- **No copied third-party files.** All content is original synthesis under MIT. Ideas and
  structure may be inspired by public repos/methodologies; text is ours. Payloads are
  standard open-source primitives (PayloadsAllTheThings / PortSwigger style), not copied prose.
- **No heavy autonomous engine.** No LangGraph/multi-LLM runtime. Light Python scripts only
  (stdlib-first), safe by default, no exploit automation.
- **No exploit-as-a-service.** Scripts never fire exploits or bulk-exfiltrate. Scope-gated,
  fail-closed, discipline-first.

## 3. Design Principles

1. **Lean brain, deep references.** SKILL.md = rules + flow + reflex. Everything else routed.
2. **Self-contained.** `per-class-index.md` and `extended-scenarios.md` route to LOCAL files,
   never external skills.
3. **Load only what the target needs.** Web target never loads malware/firmware content.
4. **Evidence & honesty preserved.** 7-Question Gate, Hunter→Skeptic→Referee, no-inflation,
   fail-closed scope stay the spine.
5. **Original, consistent voice.** Every knowledge file uses the same template so the base
   reads as one system, not five stitched repos.

## 4. Target Structure

```
bounty-operator/
├── SKILL.md                      # lean always-loaded brain (~280 lines) — updated routing
├── README.md                     # install, structure, design notes — updated
├── references/                   # workflow depth (existing, kept/extended)
│   ├── recon-playbook.md
│   ├── system-modeling.md
│   ├── high-value-classes.md
│   ├── validation-gate.md
│   ├── chaining.md
│   ├── coverage-and-memory.md
│   ├── reporting.md
│   ├── nuclei-workflow.md
│   ├── per-class-index.md        # REWRITTEN → routes to local knowledge/ + domains/
│   └── extended-scenarios.md     # REWRITTEN → routes to local domains/
├── knowledge/                    # absorbed KB — original synthesis, trigger-loaded
│   ├── README.md                 # index of the knowledge base
│   ├── vuln-classes/             # one file per web2 class (root-cause, detect, bypass, ladder, paid example)
│   │   ├── idor-bola.md
│   │   ├── ssrf.md
│   │   ├── xss.md
│   │   ├── sqli.md
│   │   ├── auth-bypass.md
│   │   ├── business-logic.md
│   │   ├── race-conditions.md
│   │   ├── oauth-oidc.md
│   │   ├── file-upload.md
│   │   ├── graphql.md
│   │   ├── ssti.md
│   │   ├── xxe.md
│   │   ├── nosqli.md
│   │   ├── command-injection.md
│   │   ├── lfi-rce.md
│   │   ├── deserialization.md
│   │   ├── api-misconfig.md      # mass assignment, JWT, prototype pollution, CORS
│   │   ├── http-smuggling.md
│   │   ├── cache-poisoning.md
│   │   ├── ssrf-cloud.md         # cloud-metadata + infra misconfig
│   │   ├── subdomain-takeover.md
│   │   ├── mfa-bypass.md
│   │   ├── saml-attacks.md
│   │   └── llm-ai.md             # ASI01-ASI10, prompt injection, chatbot IDOR
│   ├── payloads/                 # per-class payload arsenals
│   │   ├── xss.md · ssrf.md · sqli.md · ssti.md · xxe.md · nosqli.md
│   │   ├── command-injection.md · lfi.md · idor.md · path-traversal.md
│   │   └── smuggling.md
│   ├── bypass-tables.md          # SSRF-IP / open-redirect / upload / WAF / 403
│   ├── disclosed-patterns.md     # distilled patterns from disclosed reports (per class)
│   └── enterprise-matrices.md    # M365 / Okta / vCenter / SSL-VPN attack matrices
├── domains/                      # "everything" scope, each loaded independently
│   ├── web3-audit.md             # solidity/rust, 10 DeFi classes, token/meme rug vectors
│   ├── mobile.md                 # APK/IPA runtime-first, pinning bypass, secret sweep
│   ├── credential-attack.md      # spray pipeline, modes, guardrails
│   ├── cicd-security.md          # GH Actions injection, secret exfil, runner poisoning
│   ├── reverse-engineering.md    # APK/binary/firmware/.NET/JS deobf routing + toolchain
│   ├── malware-analysis.md       # triage, sandboxing, IOC extraction (defensive)
│   └── ctf.md                    # category playbooks, sandbox orchestration
└── scripts/                      # deterministic discipline tools (no network exploits)
    ├── scope_check.py            # existing — fail-closed scope
    ├── ledger.py                 # existing — coverage ledger
    ├── recon_wrap.py             # NEW — orchestrate subfinder/httpx/gau/nuclei, scope-gated
    └── chain_helper.py           # NEW — suggest chains from a finding class
```

## 5. Content Template (every vuln-class file)

```
# <Class>
> one-line: what it is, why it pays
## Root cause          — the developer mistake / mental model gap
## Where it hides      — endpoints/features/params to hunt first
## Detection           — how to find it (grep patterns, request shapes, tools)
## Minimum-evidence bar — what PROVES it (impact, not a 200) — mirrors validation-gate
## Bypass / depth      — payload ladder + WAF/filter bypass (link payloads/<class>.md)
## Chain potential     — what it escalates into (link chaining.md)
## Real paid example   — a realistic disclosed-style scenario + rough payout band
## Rejected variants   — what NOT to submit for this class
```

Domain files follow an analogous template (scope trigger → toolchain → workflow → evidence
bar → route back to phases 4-8 of the Operational Flow → reporting notes).

## 6. Script Contracts

- **recon_wrap.py** — stdlib + optional external binaries; degrades gracefully when a tool is
  absent (prints install hint). Every candidate host passes `scope_check.py` before any
  network call. `--dry-run` prints the plan without touching the network. Throttled by default.
- **chain_helper.py** — pure local logic; input a finding class, output candidate chain
  ladders (from `chaining.md` data) ranked by payout impact. No network.

Both: `--help`, exit codes, no exploit firing, no bulk exfil.

## 7. Build Phases

1. **Core rewire** — update SKILL.md routing to local paths; rewrite `per-class-index.md` +
   `extended-scenarios.md` to route locally; update README + structure.
2. **Knowledge: vuln-classes** — 24 class files (template above).
3. **Knowledge: payloads + bypass-tables + disclosed-patterns + enterprise-matrices.**
4. **Domains** — 7 domain files.
5. **Scripts** — recon_wrap.py + chain_helper.py.
6. **Verify** — every route in SKILL.md / indexes resolves to an existing local file
   (link-check); scripts run `--help` + a smoke test; README structure matches disk.

Phases 2-4 (bulk original content) are parallelizable across subagents with the fixed
template; core + verify are done on the main thread.

## 8. Success Criteria

- SKILL.md still ~280 lines, no external-skill dependency remains in any route.
- Every `references/` and inline route points to a file that exists in-repo.
- A web hunt loads only web content; RE/malware only load when that domain is invoked.
- Scripts run, are scope-gated, and never exploit.
- Content is original, MIT, one consistent voice.
- README structure block matches the actual tree.
