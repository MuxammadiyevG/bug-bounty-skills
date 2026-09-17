# CTF

> One-line: load for a Capture-The-Flag challenge in a sanctioned competition/lab; yields flags via category-specific playbooks (pwn, rev, web, crypto, forensics, misc).

## When to load this
- The engagement is an explicit CTF or training lab (jeopardy or A/D), not a live production target.
- A challenge is tagged by category, or you're triaging which category a challenge belongs to.
- You need a fast, systematic solve approach and flag-handling hygiene.
- **Framing:** CTF targets are sanctioned and self-contained — the scope/authorization gate is satisfied by the competition itself. Everything else stays disciplined.

## Toolchain (by category)
Missing tools are skipped, not errors — adapt.
- **pwn:** `pwntools` (exploit dev), `gdb`+`pwndbg`/`gef`, `checksec`, `ROPgadget`/`ropper`, `one_gadget`, `patchelf`, `libc-database`.
- **rev:** `Ghidra`/`IDA`/`Binary Ninja`, `radare2`/`rizin`, `angr` (symbolic execution), `strace`/`ltrace`, `dnSpy` (.NET), `jadx` (Android). See `reverse-engineering.md`.
- **web:** Burp/`ffuf`/`gobuster`, `sqlmap`, browser DevTools, `jwt_tool`. Route class depth to the web skills in ../SKILL.md.
- **crypto:** `SageMath`, `pycryptodome`, `RsaCtfTool`, `z3`, `hashcat`/`john`, CyberChef.
- **forensics:** `wireshark`/`tshark`/`scapy` (pcap), `volatility3` (memory), `binwalk`/`foremost` (carving), `exiftool`, `steghide`/`zsteg`/`stegsolve` (stego), `autopsy`, `bulk_extractor`.
- **misc:** whatever the puzzle demands — `pwntools` for netcat services, `z3` for constraint puzzles, scripting glue.

## Workflow
Read the prompt/title/points/attachments first — they encode hints (title puns, point value = difficulty). Then apply the category playbook.

**pwn (binary exploitation)**
Shape: a service/binary with a memory-safety bug; get a shell or read the flag.
Solve: `checksec` (NX/PIE/canary/RELRO) → find the bug (overflow, fmt string, UAF, off-by-one) → build the primitive (leak → defeat ASLR/canary, then control RIP) → ROP/ret2libc/ret2system → `pwntools` script local, then remote. `one_gadget` + libc-database when a libc is provided.

**rev (reverse engineering)**
Shape: a binary that validates a key/flag or transforms input.
Solve: `strings`/`file` first → decompile in Ghidra → find the check/transform → recover the algorithm; either invert it by hand, feed constraints to `angr`/`z3`, or patch the check and run. Confirm dynamically.

**web**
Shape: a web app with a planted vuln (SQLi, SSTI, IDOR, LFI→RCE, deserialization, JWT).
Solve: map endpoints/params → identify the class from behavior → exploit with the matching technique → the flag is usually in a DB row, a file (`/flag`), an env var, or admin-only page. Read source if provided (`.git`, backup files, source disclosure).

**crypto**
Shape: broken/weak crypto — RSA with bad params, ECB, reused nonce/keystream, padding oracle, weak PRNG.
Solve: identify the scheme → match the known attack (small `e`/Wiener/common-modulus/Håstad for RSA; ECB cut-and-paste; nonce reuse for stream/GCM; padding oracle for CBC) → SageMath/`z3`/`RsaCtfTool` to execute. Recognize the attack from the parameters given.

**forensics**
Shape: pcap, disk/memory image, or a file with hidden data.
Solve: pcap → `tshark`/follow streams, extract files/creds; memory → `volatility3` (pslist, cmdline, filescan, dumpfiles); files → `binwalk`/`foremost` to carve, `exiftool` for metadata, stego tools for images/audio. Look for the flag in transferred files, process memory, or embedded data.

**misc**
Shape: anything — jails (Python/bash escape), esolangs, OSINT, scripting, constraint puzzles.
Solve: read carefully, identify the constraint, script the interaction (`pwntools` for netcat), brute or solve (`z3`) as fits. Sandbox/jail escapes: enumerate what's allowed, build the payload from primitives.

## Flag hygiene
- Know the flag format (usually `flag{...}` / `CTF{...}`) and grep for it: `grep -rEo 'flag\{[^}]*\}'`.
- Submit exactly as found — don't mangle case/whitespace or trim wrapping.
- Log each solved flag + the path to it, so a teammate can reproduce and you don't re-solve.
- Don't leak flags/solutions publicly during a live event; respect competition rules.

## Sandbox orchestration
- Run each challenge in its own disposable container/VM — untrusted binaries and payloads shouldn't touch your host.
- One workspace dir per challenge (attachments, notes, exploit script) — keeps parallel challenges from colliding.
- For pwn/rev, match the target's libc/arch in the sandbox so local exploits port cleanly to remote.

## Evidence bar
- The **flag**, submitted and accepted — that's the whole game.
- A reproducible solve script/notes so the result isn't a fluke and a teammate can rerun it.
- Not sufficient: a partial leak, a crash without control, or a decrypt that doesn't yield the flag format.

## Feed back into the flow
Plugs into ../SKILL.md Operational Flow phases 4–8 (competition-adapted):
- **4 MODEL & RANK** — triage the challenge set: solve by points-per-effort, category strength, and low-hanging fruit first.
- **5 HUNT** — the category playbook is the hunt.
- **6 VALIDATE** — the flag being accepted is the validation gate; a "working" exploit that yields the wrong string isn't done.
- **7 CHAIN** — multi-stage challenges chain primitives (leak → exploit; foothold → privesc → flag), same discipline as bug chaining.
- **8 REPORT** — write a short solve/writeup after the event (approach, key insight, script) for the team knowledge base.

## Pitfalls
- Ignoring the prompt/title hints and brute-forcing what a clue already told you.
- Misclassifying the category and reaching for the wrong toolchain (e.g. treating a crypto weakness as a rev problem).
- Running untrusted challenge binaries on your host instead of a sandbox.
- Over-engineering: many challenges have an intended short path — try the obvious weakness before building `angr`.
- Fumbling flag submission (wrong format/whitespace) and burning attempts.
- Not saving exploit scripts, then losing the solve when infra resets or you need to re-demo.
