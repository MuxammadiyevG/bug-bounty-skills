# File Upload → RCE / Stored Payload

> Get the server to store a file it will later execute or serve in a dangerous context. Best case is RCE; common case is stored XSS or SSRF via the parser.

## Root cause
Upload validation checks the wrong thing (client-side, extension only, `Content-Type` header) or checks the right thing weakly, and the storage location is web-accessible or handed to an interpreter. The gap: "it's an image upload" — but the server trusts the filename/MIME the client sent, or a parser fetches/executes embedded content.

## Where it hides
- Avatar/profile pictures, document/attachment upload, import (CSV/XML/ZIP), resume/portfolio, invoice/logo, chat attachments.
- Image processors (ImageMagick, GraphicsMagick), PDF/Office generators, XML/SVG parsers, ZIP extractors (zip-slip).
- Endpoints that return the file back inline, or serve from a path under the app root.
- "Import from URL" variants (→ SSRF, see ssrf.md).

## Detection
- Upload a benign file, note the stored path, filename transform, and whether it's served with an executable handler.
- Test what's validated: change extension (`.php`, `.phtml`, `.jsp`, `.aspx`), `Content-Type`, magic bytes independently — which one gates?
- SVG/HTML upload rendered inline → stored XSS. XML → XXE (see xxe.md). Image lib → known CVE (ImageTragick).
- ZIP → path traversal on extraction (`../../`). Check filename traversal (`../`, null byte, double-extension).

## Minimum-evidence bar
The stored file **executes or fires in a victim/server context**: code execution (a command runs / callback from the shell), stored XSS that runs in another user's session, or the parser makes an OOB request you control (SSRF/XXE). Mirror `../../references/validation-gate.md`: uploading a `.php` that returns 200 but is served as text is not RCE — show execution or the fired payload.

## Depth ladder
1. Direct exec: upload `.php`/`.jsp`/`.aspx` to a web-served, interpreter-enabled path → hit it → command runs.
2. Double/alt extension & case: `shell.php.jpg`, `.pHp`, `.php5`, `.phtml`, `.php%00.jpg`, trailing dot/space.
3. `.htaccess`/`web.config` upload to redefine handlers, then upload the payload.
4. Polyglot: valid image + embedded code (GIF/PHP), content-sniffing abuse.
5. SVG/HTML → stored XSS in the origin (see xss.md).
6. XML/DOCX/SVG → XXE → file read / SSRF (see xxe.md).
7. Image-parser CVE (ImageTragick `msl:`/`ephemeral:`) → RCE/SSRF.
8. ZIP-slip path traversal → write outside the target dir → overwrite a served/executed file.
See `../payloads/lfi.md` and `../payloads/path-traversal.md` for retrieval/traversal.

## Bypass notes
- Client-side check only → send the raw multipart to the API.
- Extension allow-list → double extension, null byte, case, alternate exec extensions, trailing chars.
- MIME check → forge `Content-Type` while keeping payload; magic-byte prefix a valid image header.
- Filename sanitization → traversal in the `filename` field, or via the ZIP entry names. See `../bypass-tables.md` (file-upload bypass table).

## Chain potential
Upload → webshell → RCE → infra. SVG → stored XSS → ATO. XML upload → XXE → SSRF → cloud creds. Traversal write → overwrite config → auth bypass. See `../../references/chaining.md`.

## Real paid example
Real disclosed reports:
- **Unrestricted file upload on [ambassador.mail.ru]** (Mail.ru, $3000) — hackerone.com/reports/854032 — no real server-side type validation on the upload.
- **External SSRF and Local File Read via video upload due to vulnerable FFmpeg HLS processing** (TikTok, $2727) — hackerone.com/reports/1062888 — uploaded media parsed by FFmpeg fetched/read files (parser-side SSRF/LFR).
- **Webshell via File Upload on ecjobs.starbucks.com.cn** (Starbucks, bounty undisclosed) — hackerone.com/reports/506646 — an uploaded webshell landed in an executable path.
- **[ RCE ] Through stopping the redirect in /admin/* the attacker able to bypass Authentication And Upload Malicious File** (Mail.ru, bounty undisclosed) — hackerone.com/reports/683957 — auth bypass then malicious file upload to RCE.

**The recurring tell:** the server validates the wrong thing (client-side, Content-Type, extension) or hands the file to a parser — either the file lands in a web-executed path as a shell, or the parser (FFmpeg, image lib) fetches/reads on your behalf.

## Rejected variants
- `.php` uploaded but stored where it's never executed (served as download/text).
- Self-XSS via an SVG only you view.
- "Missing file-type validation" with no payload that fires.
- Upload of oversized files (DoS) with no code/parser impact, when out of scope.
- Path stored but not reachable and not executed.
