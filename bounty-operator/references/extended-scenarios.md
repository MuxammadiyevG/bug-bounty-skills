# Extended Scenario Routing — beyond web apps

> bounty-operator's core is web/API hunting, but modern engagements cross into APK teardown, binary
> analysis, JS deobfuscation, firmware, CTF, web3, credential attack, and CI/CD. Each scenario has a
> **local domain playbook** in `domains/`. Load the matching one; it carries the toolchain, workflow,
> evidence bar, and how results plug back into the Operational Flow. Nothing here needs an external skill.

## Routing table — scenario → local playbook

| Signal / scenario | Open this file |
|---|---|
| `.apk` / `.ipa`, Android/iOS app, mobile API, SSL-pinned traffic | `domains/mobile.md` |
| Solidity/Rust contract, DeFi/TVL target, token / meme-coin rug check | `domains/web3-audit.md` |
| Login portal + employee list, O365/Okta, "should I spray?" | `domains/credential-attack.md` |
| Public repo, GitHub Actions / GitLab CI / Jenkins, workflow files | `domains/cicd-security.md` |
| `.exe`/`.dll`/`.so`/`.elf` binary, firmware `.bin`, .NET assembly, obfuscated JS, encrypted params | `domains/reverse-engineering.md` |
| Suspicious binary, malware sample, YARA/triage (defensive) | `domains/malware-analysis.md` |
| CTF challenge, flag format, category-based solve | `domains/ctf.md` |

Each domain file is self-contained: **when to load → toolchain → workflow → evidence bar → feed back
into phases 4-8 → pitfalls.** Read the file before running commands — stop guessing tool invocations.

## The one insight that unifies the non-web domains

A shipped client (mobile app, desktop binary, firmware, obfuscated JS) is a **copy of the backend
contract**. Reverse it for endpoints, secrets, hidden params, and request-signing/encryption logic
the web UI never exposes — then feed every extracted endpoint and secret straight back into the
web/API hunt (phase 5 of the Operational Flow). The highest-value endpoints are usually the ones the
UI never links to.

## Integration with the Operational Flow

- **Phase 2–3 (recon):** APK teardown and JS deobfuscation feed new endpoints into the surface map.
- **Phase 4 (model):** binary/firmware/contract analysis reveals auth schemes, crypto, trust assumptions.
- **Phase 5 (hunt):** reversed request-signing lets you modify "protected" params (price, role, userId)
  for authz/business-logic testing the WAF can't see.
- **Phase 6–8 (validate/chain/report):** the same gates apply — the 7-Question Gate doesn't care how
  you found it; it cares whether it's real, in scope, and impactful.

## Optional external deep-dive

If `reverse-skill` (github.com/zhaoxuya520/reverse-skill) or other specialist skills are installed
alongside, the domain files note where to defer to them for even deeper per-scenario playbooks. They
are optional — the `domains/` files stand on their own.

## Tool availability check

Before starting any scenario, verify the required tools are installed. Missing tools are *skipped, not
errors* — adapt the workflow to what's available.

```bash
# Quick check for common tools (edit the list per domain)
for tool in jadx apktool frida objection nuclei binwalk slither; do
  command -v "$tool" >/dev/null 2>&1 && echo "OK: $tool" || echo "MISSING: $tool"
done
```
