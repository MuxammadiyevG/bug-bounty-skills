# LFI / File Inclusion → RCE

> A traversal that reads files is a start; the payout is turning inclusion into code execution. PHP filter chains, log/environ poisoning, and wrappers do it without an upload.

## Root cause
User input reaches a file-load sink (`include`, `require`, `readfile`, `fopen`, template loaders,
`file_get_contents`) without canonicalization or an allowlist. In PHP the sink also honors stream
wrappers (`php://`, `data://`, `phar://`, `expect://`) and `.ini`/`.htaccess` auto-prepend behavior,
which is what upgrades read-only LFI into execution.

## Where it hides
- `?page=`, `?template=`, `?lang=`, `?file=`, `?view=`, theme/skin selectors.
- Download/export endpoints that echo file contents.
- Locale/i18n loaders, PDF/report template pickers.
- Framework routers that map a param to a filesystem path.
- Log-processing or "preview" features.

## Detection
- Read a known file: `../../../../etc/passwd`, `..\..\..\windows\win.ini`, or the app's own config.
- `php://filter/convert.base64-encode/resource=index.php` → base64 source disclosure confirms wrapper
  support and hands you the code to find the next bug.
- Null-byte only on ancient PHP; more often the app appends `.php` — chain a wrapper or a poison sink.

## Minimum-evidence bar
LFI: sensitive file content in the body (app source, a config with a live secret) — not just a
traversal that 200s. RCE: your injected code actually executes (a marker in output, or an OOB
callback), demonstrated with one harmless command. Reading `/etc/passwd` proves read; it does not
prove RCE — say which you have. Prove and stop; never exfiltrate real secrets in bulk.

## Depth ladder
1. Confirm traversal → read app source via `php://filter`.
2. **iconv filter-chain RCE** — chain `php://filter` convert steps to synthesize a payload in the
   include stream, executing with no writable upload. The modern no-upload path.
3. **Log poisoning** — inject PHP into a value that lands in an included/readable log
   (User-Agent, auth log, access log), then include the log.
4. **`/proc/self/environ`** — poison an env-reflected value, include environ.
5. **Session inclusion** — control a session var, include the session file.
6. **`.user.ini` / `.htaccess` auto_prepend** — if you can drop one, force prepend of your file.
7. **Wrappers** — `data://` / `expect://` where enabled.
See `../payloads/lfi.md` and `../payloads/path-traversal.md`.

## Bypass notes
- Appended extension → nested/null-byte (legacy), wrapper chains, or a poison sink that already ends `.log`.
- Traversal filters → over-long `....//`, encoded `%2e%2e%2f`, double-encode `%252e`, UTF-8 overlong,
  `..%c0%af`. Path allowlist prefixes → `allowed/../../../etc/passwd`.
See `../bypass-tables.md`.

## Chain potential
LFI → source disclosure → find hardcoded secrets/second bug. LFI → RCE = chain endpoint. RCE → cloud
metadata/env creds → infra. See `../../references/chaining.md`.

## Real paid example
Real disclosed reports:
- **Path traversal, to RCE** (GitLab, $12000) — hackerone.com/reports/733072 — file-path traversal escalated into code execution.
- **Path traversal, SSTI and RCE on a MailRu acquisition** (Mail.ru, $2000) — hackerone.com/reports/536130 — traversal chained with template injection into RCE.
- **Worker container escape lead to arbitrary file reading in host machine [again]** (Semmle, $2000) — hackerone.com/reports/697055 — arbitrary file read on the host from a worker container.
- **HTML-injection in PDF-export leads to LFI** (Visma Public, $500) — hackerone.com/reports/809819 — a PDF renderer resolved local file paths from injected HTML.

**The recurring tell:** a param or renderer that maps input to a filesystem path with no canonicalization — traversal first proves the read, then a wrapper/log/template sink turns that read into execution.

## Rejected variants
- Traversal returns a 200 but the body is unchanged / no file content — not confirmed LFI.
- Reading a world-readable non-sensitive file (a default banner) with no secret and no RCE path.
- "Include works but only wrappers are disabled and nothing writable" reported as RCE — it's read-only.
- Client-side path traversal in a static asset server with no sensitive files behind it.
