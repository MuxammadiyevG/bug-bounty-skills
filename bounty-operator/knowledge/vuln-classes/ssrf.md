# SSRF

> You make the server fetch a URL you control. Reaches internal services, cloud metadata, and credentials the internet can't touch — routinely critical.

## Root cause
The app treats a user-supplied URL/host as data and hands it to an HTTP/socket client with the *server's* network position and trust. The gap: "it's just fetching an image / webhook / preview" — no allow-list, DNS re-resolves after the check, or the SSRF is blind and assumed harmless.

## Where it hides
- URL-taking features: webhooks, "import from URL", link previews/unfurlers, PDF/screenshot/thumbnail render, avatar-by-URL, RSS/feed readers, SSO/OIDC metadata & JWKS URLs.
- Server-side integrations: `?url=`, `?next=`, `?dest=`, `?callback=`, `?image=`, `?proxy=`, `?feed=`, `?webhook=`.
- File parsers that fetch: XML (XXE→SSRF), SVG, PDF with remote resources, Office docs, HTML sanitizers that resolve remote CSS/`<img>`.
- API gateways / headless browsers / CI runners that render user content.

## Detection
- Point the sink at an OOB collector you control (Burp Collaborator, `interactsh`) — DNS **and** HTTP hit = proof.
- Differential timing/response between an internal host (`127.0.0.1:22`, `169.254.169.254`) and a dead port.
- Grep JS/OpenAPI for URL params; `param-discover` for hidden `url`/`callback`.
- Blind: rely on OOB. Semi-blind: watch response length/status/timing per port for internal scan.

## Minimum-evidence bar
An OOB callback **you control** fired by the server, or an **internal-only response body** returned to you (metadata JSON, an intranet page, a port banner). Mirror `../../references/validation-gate.md`: a hung request or a DNS lookup with no attacker-controlled callback is not proof. Non-impactful/DNS-only SSRF is on the always-rejected list — escalate to a real internal target or a read.

## Depth ladder
1. Confirm OOB (DNS + HTTP callback).
2. Hit cloud metadata: AWS `http://169.254.169.254/latest/meta-data/`, IMDSv2 token dance, GCP `metadata.google.internal` (`Metadata-Flavor: Google`), Azure `?api-version`. Pull a credential.
3. Internal port/host scan via timing/length differentials; reach admin panels, `localhost` dashboards, k8s `10.*`.
4. Read internal services: Redis, Elasticsearch, `.internal` APIs, `file://`, `gopher://` for raw TCP (Redis/SMTP).
5. Protocol smuggling: `gopher://` to forge POST bodies; `dict://`.
6. Turn blind→full: force an error that reflects the fetched body, or exfil via a service that echoes.
See `../payloads/ssrf.md` for wrappers and metadata paths.

## Bypass notes
- Filter allow-lists a domain → `attacker.com@internal`, `internal#.attacker.com`, DNS rebinding (TTL 0), `nip.io`/`sslip.io`.
- IP encodings: decimal `2130706433`, octal `0177.0.0.1`, hex `0x7f000001`, IPv6 `[::1]`, `[::ffff:127.0.0.1]`, short `127.1`.
- Scheme filter → `//`, case, `http:\\`, redirect via an open-redirect you host (302 to internal). See `../bypass-tables.md`.
- IMDSv2 → obtain the `X-aws-ec2-metadata-token` via PUT if the client forwards headers.

## Chain potential
SSRF → metadata → temp cloud creds → cloud API read → **infra/data breach**. SSRF → internal admin action. XXE/file-upload → SSRF. See `../../references/chaining.md`.

## Real paid example
Marketing tool "preview link" fetched arbitrary URLs server-side. Pointed at IMDSv2, retrieved the instance role's STS credentials, listed an S3 bucket of customer exports. Band: **$5k–$15k+** (cloud cred → data).

## Rejected variants
- DNS-only pingback with no internal reach or read.
- Fetching an external site the app is *designed* to fetch (public unfurl) with no internal access.
- "Server made a request" with no attacker-controlled destination confirmed.
- Self-hosted/localhost-only PoC on your own box.
