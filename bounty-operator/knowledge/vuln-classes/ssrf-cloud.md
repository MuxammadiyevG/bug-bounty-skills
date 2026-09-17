# Cloud Metadata / Infra Misconfig

> SSRF that reaches an instance metadata service, plus exposed buckets and leaked cloud creds.
> The classic SSRF → IMDS → temporary credentials → cloud API chain. Infra-level payouts.

## Root cause
- **IMDS reach:** a server-side fetch (SSRF) can address the link-local metadata endpoint
  (`169.254.169.254`, GCP `metadata.google.internal`, Azure `169.254.169.254/metadata`), and IMDSv1
  (no token) hands out role credentials to anything that asks.
- **Exposed storage:** buckets/blobs with public or misconfigured ACLs (list/read/write), or
  predictable names.
- **Leaked creds:** long-lived keys in JS bundles, git history, mobile apps, error pages, or env
  echoed by a debug endpoint.

## Where it hides
- Any URL-fetching feature: webhooks, "import from URL", PDF/screenshot/preview generators, avatar
  fetch, SSO metadata fetch, link unfurlers, RSS/import.
- `<img>`/SVG/HTML→PDF renderers (blind SSRF via resource loads).
- Storage: `*.s3.amazonaws.com`, `storage.googleapis.com`, `*.blob.core.windows.net` tied to an
  in-scope app. An in-scope subdomain backed by S3 is still in scope.
- Frontend bundles / repos for `AKIA…`, `AIza…`, service-account JSON, connection strings.

## Detection
- SSRF: point the fetch at an OOB collaborator to confirm outbound; then at IMDS variants. Watch for
  an internal-only body returned or an OOB DNS/HTTP hit.
- IMDSv2 needs a PUT-token first — test whether the SSRF primitive can set headers/methods.
- Buckets: try list, then read a single object, then a benign write to a test key you delete.
- Creds: validate a found key with a **read-only, non-destructive** identity call (`sts
  get-caller-identity` equivalent) — identity confirmation, not resource enumeration.

## Minimum-evidence bar
SSRF: an OOB callback you control, or an internal-only response body — a hung request is not proof.
IMDS: the actual credential/role response returned to you (redact before reporting). Bucket: the
*sensitive* object content or a proven write, not a public-by-design asset. Leaked key: proven live
via one identity call — not a random-looking string. Prove access with the minimum (one object, one
identity call), then stop. Never enumerate the account or touch production data.

## Depth ladder
1. Confirm SSRF (OOB) → reach IMDS.
2. Pull role creds from IMDSv1 (or bypass to IMDSv2 if header control exists).
3. Confirm creds live with one identity call — stop there; do not list/read resources.
4. Buckets: read one sensitive object / prove write. Leaked keys: identity-confirm only.
See `../payloads/ssrf.md`.

## Bypass notes
- IMDS filters/allowlists → alternate IP encodings (decimal, octal, hex, IPv6-mapped), DNS rebinding,
  `[::ffff:169.254.169.254]`, redirect-to-metadata, enclosed-alphanumerics. See `../payloads/ssrf.md`
  and `../bypass-tables.md`.
- Scheme filters → `gopher://` for raw requests where the fetcher allows it.

## Chain potential
SSRF → IMDS creds → cloud read = the canonical infra chain. Leaked key → cloud API → data/infra.
Bucket write → poison a served JS bundle → stored XSS/mass impact. See `../../references/chaining.md`.

## Real paid example
Real disclosed reports:
- **Server Side Request Forgery (SSRF) at app.hellosign.com leads to AWS private keys disclosure** (Dropbox, $4913) — hackerone.com/reports/923132 — SSRF pivoted to AWS credential/key disclosure.
- **Server-Side Request Forgery using Javascript allows to exfill data from Google Metadata** (Snapchat, bounty undisclosed) — hackerone.com/reports/530974 — reached the GCP metadata endpoint and exfiltrated it.
- **SSRF leaking internal google cloud data through upload function [SSH Keys, etc..]** (Vimeo, bounty undisclosed) — hackerone.com/reports/549882 — an upload-fetch SSRF read GCP metadata including SSH keys.
- **Full read SSRF in www.evernote.com that can leak aws metadata and local file inclusion** (Evernote, bounty undisclosed) — hackerone.com/reports/1189367 — full-response SSRF reaching AWS metadata plus LFI.

**The recurring tell:** a server-side fetch (upload, PDF/preview, import) with no egress control pointed at the link-local metadata IP — the response carries role credentials or SSH keys straight back to you.

## Rejected variants
- SSRF that only does DNS resolution / hits an OOB but reaches nothing internal and no metadata.
- A public-by-design bucket (marketing assets) reported as "exposed data".
- A key-shaped string with no proof it's live (test it read-only or drop it).
- IMDSv2 enforced and no header/method control — SSRF confirmed but no credential path; report the
  SSRF at its real (lower) impact, no inflation.
