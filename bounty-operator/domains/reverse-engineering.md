# Reverse Engineering

> One-line: load when the objective is locked inside a compiled/obfuscated artifact (native binary, APK, minified JS, .NET assembly, firmware); yields recovered endpoints, secrets, and request-signing/encryption schemes that unlock "protected" params the WAF never sees.

## When to load this
- A client hides logic in a binary/blob: native app, thick client, mobile lib, firmware image, obfuscated web bundle.
- Requests are signed/encrypted so Burp-tampered traffic is rejected — you need the scheme to attack it.
- Recon needs the base URLs, endpoints, or keys that only exist compiled into a shipped artifact.
- A CTF/rev challenge, or a security question that requires understanding what a binary actually does.
- **Why RE pays in bug bounty:** reversing request-signing or client-side encryption lets you forge/modify "protected" parameters. The server trusts them because the WAF and validation assume only the official client can produce them — so authz and business-logic bugs behind that trust become reachable.

## Toolchain (route by artifact type)
Missing tools are skipped, not errors — adapt.
- **Native binary (ELF/PE/Mach-O):** `Ghidra` (free, decompiler), `IDA Pro` (best-in-class), `radare2`/`rizin` (scriptable CLI), `Binary Ninja` (fast, clean IL). Plus `strings`, `nm -D`, `objdump`, `ltrace`/`strace`, `gdb`/`pwndbg`.
- **APK / DEX:** `jadx` (DEX→Java), `apktool` (smali + resources), `frida`/`objection` (runtime). See `mobile.md` for the full mobile flow.
- **Minified/obfuscated JS:** browser DevTools pretty-print + source maps if leaked, `de4js`/webcrack for common packers, `AST` tools (Babel) for control-flow deobf, and just reading it with a mental interpreter.
- **.NET (CLR):** `dnSpy`/`dnSpyEx` (decompile + live debug + edit), `ILSpy`, `de4dot` (deobfuscate/unpack ConfuserEx etc.).
- **Firmware:** `binwalk` (carve filesystems), `unblob`, `firmware-mod-kit`, `EMBA` (automated firmware analysis pipeline), then RE the extracted binaries with the native toolchain.
- **Packers/general:** `Detect It Easy (DIE)`, `UPX -d`, `capa` (capability detection), `xxd`/`hexdump`.

## Workflow
1. **Triage the artifact.** File type (`file`, DIE), architecture, packed/obfuscated? Unpack first (`upx -d`, unblob, de4dot) — RE'ing packed code wastes hours.
2. **Cheap wins before decompiling.** `strings` + grep for URLs, keys, format strings, error messages; imports (`nm -D`, PE import table) for crypto/network APIs; `capa` for behaviors. Often the endpoint or key is right there.
3. **Follow the decision tree to the right tool** (above) — don't open Ghidra for minified JS or dnSpy for an ELF.
4. **Anchor to the interesting function.** Don't read the whole binary. Pivot from a string ("Invalid signature", a URL, an error), an import (`HMAC`, `AES`, `curl`, `SecKeyCreateSignature`), or a runtime hook (Frida on the send/sign call) to the exact routine that matters.
5. **Recover the mechanism.** For request signing: find where the payload is HMAC'd/signed — the algorithm, the key (hardcoded? derived? device-bound?), and which fields are covered. For encryption: the cipher, mode, key, IV derivation. Confirm by reproducing one known request's signature offline.
6. **Weaponize for BB.** With the scheme reproduced, build a small script/Burp extension that re-signs/re-encrypts arbitrary payloads. Now tamper the "protected" params (IDs, prices, roles) and attack authz/logic normally — the server accepts them because they're validly signed.
7. **Harvest for recon.** Every recovered base URL, hidden/debug endpoint, API key, and feature flag goes back to the recon/surface map. Compiled artifacts routinely leak staging URLs and endpoints the live web app never references.
8. **Verify dynamically.** Confirm static conclusions at runtime (gdb/Frida/dnSpy debugger) rather than trusting a decompiler's guess — decompilers hallucinate types and control flow.

## Evidence bar
- A reproduced signature/ciphertext for a request the client never sent, accepted by the server — proving you own the signing/encryption scheme.
- A tampered-but-valid request that yields an authz/logic bug (another user's data, a price change, elevated role) — the RE is the enabler, the impact is the finding.
- A recovered secret **proven live** against its service, or a hidden endpoint confirmed reachable.
- For a rev/CTF task: the correct flag, or a precise description of the algorithm/keygen with a working solver.
- Not evidence: "I found a string that might be a key," a decompiler screenshot with no confirmed behavior, an endpoint you never probed.

## Feed back into the flow
Plugs into ../SKILL.md Operational Flow phases 4–8:
- **4 MODEL & RANK** — recovered endpoints/keys/flags expand the surface map; the client-trust boundary you just broke becomes a top-ranked target.
- **5 HUNT** — once you can forge valid requests, hunt authz/logic on the now-reachable params exactly as for a normal API.
- **6 VALIDATE** — reproduce the signature/behavior deterministically; a lucky one-off decompile read is not proof.
- **7 CHAIN** — recovered key → signed request forgery → BOLA/price manipulation; leaked endpoint → unauth admin API; firmware key → device fleet compromise.
- **8 REPORT** — show the recovered scheme concisely and the resulting impact; the triager needs the forged-request recipe, not a Ghidra tour.

## Pitfalls
- Reverse-engineering a packed/obfuscated blob without unpacking first — you're reading garbage.
- Boiling the ocean: reading the whole binary instead of anchoring to the one function that signs/encrypts/validates.
- Trusting decompiler output as ground truth — verify types and branches dynamically before building an exploit on them.
- Treating the recovered key/endpoint as the finding; the finding is the *impact* it unlocks — always land it on a real bug.
- Ignoring device-bound or server-issued key material — some signing keys aren't in the binary; hook the runtime instead.
- Redistributing or over-quoting proprietary decompiled source in a report — reference the mechanism, keep it minimal, stay within program rules.
