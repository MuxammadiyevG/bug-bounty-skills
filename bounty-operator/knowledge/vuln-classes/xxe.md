# XXE

> An XML parser resolves external entities you define. That reads local files, reaches internal services (SSRF), and — blind or not — exfiltrates over your own channel.

## Root cause
The XML parser is configured to process DTDs and external entities (the insecure default in many libs), and it parses attacker-supplied XML. The gap: "it's just an XML/SOAP/config/SVG/DOCX upload" — but the parser will happily fetch `file://` and `http://` entities the document declares.

## Where it hides
- Any XML intake: SOAP APIs, REST endpoints accepting `application/xml` or `text/xml`, XML-RPC.
- File formats that are XML underneath: SVG, DOCX/XLSX/PPTX, `.xml` config import, RSS/Atom, SAML, SVG avatars.
- Content-type flips: send an XML body to a JSON endpoint (`Content-Type: application/xml`) — some parsers accept it.
- PDF/SVG/image processors, sitemap/feed importers.

## Detection
- Inject a DTD with an external entity and reference it: does the value appear, or does an OOB request fire?
- In-band: `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]><r>&x;</r>` → file content reflected.
- Blind: point an entity at your OOB collector (`http://x.oast.me/`) → DNS/HTTP hit.
- Try SVG/DOCX upload with a poisoned DTD when a raw XML endpoint isn't obvious.

## Minimum-evidence bar
File content **returned to you**, or an **OOB callback you control** (blind), or an **internal-only response** reached via the parser. Mirror `../../references/validation-gate.md`: a parser error mentioning DTDs is not proof; a hung request is not proof. Read one benign file (`/etc/hostname`) or fire one controlled callback — then stop. Don't exfil secrets you don't need.

## Depth ladder
1. Classic in-band: reflect `file:///etc/passwd` (or a Windows path) into the response.
2. Blind OOB: external DTD on your server → parameter entity → DNS/HTTP callback proves parsing.
3. OOB file exfiltration: parameter-entity DTD that wraps file contents into the callback URL.
4. Error-based exfil: force the file contents into a parser error message when output isn't reflected.
5. SSRF-via-XXE: entity → internal host / cloud metadata (`http://169.254.169.254/...`) → see `ssrf.md`.
6. Upload vector: SVG/DOCX/XLSX with a poisoned DTD when the raw endpoint is filtered.
7. DoS (billion-laughs) only where in scope — usually skip.
See `../payloads/xxe.md`; for file-read targets `../payloads/lfi.md`, `../payloads/path-traversal.md`.

## Bypass notes
- `<!DOCTYPE>`/`SYSTEM` filtered → use parameter entities (`%`), external DTD, or `php://filter`-wrapped reads.
- Special chars break the read → base64 via `php://filter/read=convert.base64-encode`.
- Local DTD reuse: reference a DTD already on the target host to smuggle entities past a "no external DTD" filter.
- JSON-only endpoint → flip `Content-Type` to `application/xml`. See `../bypass-tables.md`.

## Chain potential
XXE → SSRF → cloud metadata → creds → infra. XXE → source/config read → next bug. XXE file read of secrets → ATO/admin. See `../../references/chaining.md`.

## Real paid example
A SOAP endpoint parsed request bodies with DTD processing on. `file:///etc/hostname` reflected in the response; pivoting the entity to `http://169.254.169.254/latest/meta-data/iam/` retrieved the instance role name (SSRF-via-XXE). Read one file + one metadata path, then stopped. Band: **$3k–$12k** (file read + SSRF to metadata).

## Rejected variants
- Parser error referencing DTD/entities with no file read or callback.
- Billion-laughs DoS where DoS is out of scope.
- OOB DNS lookup with no attacker-controlled callback confirmed.
- Reading a world-readable, non-sensitive file with no path to secrets or internal reach, when the program wants demonstrated impact.
