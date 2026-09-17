# Extended Scenario Routing — beyond web apps

> bounty-operator's core is web/API hunting, but modern engagements cross into APK teardown,
> binary analysis, JS deobfuscation, firmware, CTF, and more. This file routes each scenario to
> the right tool + methodology so the agent stops guessing commands.

## Routing table — scenario → toolchain → methodology

When a task hits one of these scenarios, load the matching toolchain and follow the workflow.
If `reverse-skill` (github.com/zhaoxuya520/reverse-skill) is installed alongside, defer to its
deep per-scenario playbooks. Otherwise, follow the condensed guidance below.

### Mobile / APK

| Signal | Toolchain | Workflow |
|---|---|---|
| `.apk`, Android app, mobile API | jadx, apktool, Frida, objection, MobSF | Decompile → manifest perms → exported components → hardcoded secrets → API surface → cert pinning bypass → dynamic hook → test API auth from extracted endpoints |

**Key insight:** a mobile app is a *shipped copy of the backend contract*. Decompile it for
endpoints, secrets, hidden params, and request-signing logic the web UI never exposes. Feed every
extracted endpoint and secret back into the web/API hunt (phase 5 of the Operational Flow).

Extract checklist: API base URLs, auth tokens/keys, GraphQL operations, hidden admin endpoints,
certificate pins, request-signing algorithms, feature flags, debug/staging hostnames.

### iOS / mobile (non-APK)

| Signal | Toolchain | Workflow |
|---|---|---|
| `.ipa`, iOS app, Swift/ObjC binary | class-dump, Hopper/IDA, Frida, objection, SSL Kill Switch | Decrypt (if needed) → class-dump headers → find URL schemes → extract plists for secrets → Frida hook network calls → extract API surface |

### Binary reverse engineering

| Signal | Toolchain | Workflow |
|---|---|---|
| `.exe`, `.dll`, `.so`, `.elf`, PE/ELF, "reverse this binary" | IDA Pro, Ghidra, radare2, Binary Ninja | Load → identify compiler/packer → strings → imports/exports → find main/entry → trace interesting functions → decompile critical paths → document findings |

Decision tree for tool selection:
- **IDA Pro** — gold standard for complex binaries, best decompiler for x86/x64/ARM
- **Ghidra** — free, excellent for team work, good decompiler, extensible
- **radare2/rizin** — CLI-first, scriptable, good for automation and quick triage
- **Binary Ninja** — strong HLIL/MLIL, good for automated analysis pipelines

### .NET / C# reverse engineering

| Signal | Toolchain | Workflow |
|---|---|---|
| `.dll` (managed), `.exe` (.NET), C# app | dnSpy, ILSpy, de4dot (deobfuscation) | Deobfuscate (de4dot) → decompile (dnSpy/ILSpy) → find auth/crypto logic → extract keys/endpoints → identify serialization (BinaryFormatter → deser vuln) |

### Frontend JS / encrypted params

| Signal | Toolchain | Workflow |
|---|---|---|
| Encrypted/signed request params, JS bundles, webpack, obfuscated JS | Browser devtools, AST tools, de4js, synchrony, webpack-unpack | Identify encryption function → trace key material → find the signing/encryption entry point → reconstruct the algorithm → replay requests with modified params |

**Why it matters for bug bounty:** if the app encrypts request bodies or signs params client-side,
reversing that logic lets you modify parameters the app "protects" (price, role, userId) and test
for business-logic and authz bugs the WAF can't see.

### Firmware / IoT

| Signal | Toolchain | Workflow |
|---|---|---|
| `.bin` firmware, IoT device, embedded | binwalk, firmware-mod-kit, EMBA, Firmwalker | Extract filesystem (binwalk) → find web server config → extract hardcoded creds → find debug interfaces (UART/JTAG) → analyze update mechanism → find command injection in CGI/API |

### CTF challenges

| Signal | Toolchain | Workflow |
|---|---|---|
| "CTF", challenge file, flag format | Per-category (pwn/rev/web/crypto/forensics) | Identify category → select toolchain → systematic solve → document solution |

If `reverse-skill`'s CTF-Sandbox-Orchestrator (42 sub-skills) is installed, route there for
category-specific deep playbooks.

### Malware analysis

| Signal | Toolchain | Workflow |
|---|---|---|
| Suspicious binary, malware sample, YARA | IDA/Ghidra, YARA, sandbox (ANY.RUN/VirusTotal), Process Monitor, Wireshark | **Static first:** strings, imports, PE headers, packer detection → **Dynamic:** sandbox execution, network capture, API monitoring → **Behavioral:** C2 communication, persistence, evasion techniques |

**Authorized use only.** Analyze in an isolated environment; never execute on production systems.

### Network capture / protocol analysis

| Signal | Toolchain | Workflow |
|---|---|---|
| `.pcap`, network traffic, protocol RE | Wireshark, tshark, mitmproxy, Reqable | Load capture → protocol hierarchy → filter by host/port → extract credentials/tokens → reconstruct sessions → identify vulnerable protocols |

---

## Integration with the Operational Flow

These scenarios plug into the main bounty-operator workflow:

- **Phase 2–3 (recon):** APK teardown and JS deobfuscation feed new endpoints into the surface map.
- **Phase 4 (model):** Binary/firmware analysis reveals auth schemes, crypto, and trust assumptions.
- **Phase 5 (hunt):** Reversed request-signing lets you modify "protected" params for authz testing.
- **Phase 6–8 (validate/chain/report):** Same gates apply — the 7-Question Gate doesn't care how
  you found it; it cares whether it's real, in scope, and impactful.

## Tool availability check

Before starting any scenario, verify the required tools are installed. If `reverse-skill` is
present, run its `refresh-tool-index` script. Otherwise, check manually:

```bash
# Quick check for common tools
for tool in jadx apktool frida objection nuclei; do
  command -v "$tool" >/dev/null 2>&1 && echo "OK: $tool" || echo "MISSING: $tool"
done
```

Missing tools are *skipped, not errors* — adapt the workflow to what's available.
