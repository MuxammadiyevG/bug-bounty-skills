# Recon Playbook — recon as an intelligence operation

> Recon answers two questions only: **what does this target expose to the internet**, and **which of
> those assets are likely to be vulnerable**. Every technique serves one of those. Order the work by
> signal-to-noise: start wide and passive, then narrow aggressively *before* you send any exploit.
> Recon is 60–70% of the work — but its failure mode is mapping forever and never testing. Each layer
> below has diminishing returns and an explicit stop condition.

## Table of contents
1. Passive layer (zero-touch)
2. Active layer (touches target infra)
3. Finding the origin behind a WAF/CDN
4. Client-side JS as the surface map
5. Parameter & endpoint discovery
6. Ranking the surface
7. When to STOP each layer

---

## 1. Passive layer (zero-touch — do this fully first)

No packets to the target's own app. Highest signal per unit risk.
- **Certificate transparency** (crt.sh and equivalents) — subdomains from issued certs.
- **DNS history / passive DNS** — historical A/CNAME records, dead-but-live hosts.
- **Wayback / gau / common-crawl** — historical URLs, dead endpoints, old JS still served.
- **Public code & artifacts** — GitHub/GitLab orgs, gists, Postman collections, npm/PyPI packages,
  S3/GCS/Azure buckets — for leaked secrets, internal hostnames, and API shapes.
- **Search-engine + Shodan/Censys/FOFA** — exposed services, banners, tech, favicon hashes.

**Stop condition:** you have a subdomain set that stops growing across two independent sources, plus
a first pass of leaked secrets and historical URLs. Move to active.

## 2. Active layer (touches target — throttle deliberately)

- **Subdomain enumeration** — resolver-backed brute + permutations on top of the passive set.
- **Live-host probing** — which resolve and answer HTTP(S); capture status, title, tech, redirects.
- **Tech / WAF fingerprint** — framework, server, CDN/WAF, versions → feeds the CVE and bypass path.
- **Content discovery** — directories, backups, admin panels, non-standard ports/services.

**Stop condition:** live hosts fingerprinted and ranked. Don't keep brute-forcing a flat surface —
pivot to modeling and hunting.

## 3. Finding the origin behind a WAF/CDN

Most targets sit behind Cloudflare/Akamai/etc.; the raw origin often has no WAF and no rate limit.
- **Favicon-hash pivot** — the same favicon is reused across infra; hash it and search Shodan/Censys.
  An IP that serves the target's favicon but isn't a CDN IP is a likely origin.
- **Historical IPs** — pre-CDN A records from passive DNS often still answer directly.
- **SSRF / misconfig leaks** — error pages, headers, or SSRF that reveal an internal/origin address.
Confirm an origin by requesting the app with the real Host header and comparing the response.

**Care:** hitting an origin directly can bypass protections the program relies on — stay in scope,
throttle hard, and prove impact minimally.

## 4. Client-side JS as the surface map

The JS bundle is the application's blueprint: endpoints, parameters, roles, feature flags, and
sometimes secrets the server never meant to expose. On every live host:
- Collect JS from passive history *and* live crawl (bundles, chunks, workers, source maps).
- Extract endpoints, parameter names, GraphQL operations/persisted-query hashes, and secret patterns
  (cloud keys, tokens, JWTs). For obfuscated/encrypted bundles, route the deep work to
  `domains/reverse-engineering.md` (JS deobfuscation section).
- Source maps, when present, reconstruct original source — read them.

**Why it matters:** hunters who skip JS lose the P1s — the highest-value endpoints are usually the
ones the UI never links to.

## 5. Parameter & endpoint discovery

- Mine params from history, JS, and wordlists; confirm hidden ones by response differentials.
- Reconstruct the API from OpenAPI/Swagger, GraphQL introspection (or schema recovery when it's off),
  mobile-app teardown, and Postman collections.
- Map *sequences*, not just endpoints — multi-step flows (checkout, invite, reset) are where logic
  bugs live.

## 6. Ranking the surface

Rank by likely impact, not by what's easiest to scan. Push to the top:
- Anything handling **money, PII, or auth** (billing, export, KYC, admin, invite/role).
- **New or recently changed** features (less-tested code).
- **APIs** — especially object-id endpoints and business-flow endpoints (BOLA/business-logic).
- Assets with **weak fingerprints** (old versions → CVE path) or **exposed services**.
Feed the ranked list into `system-modeling.md`, then hunt top-down.

## 7. When to STOP each layer (the anti-rabbit-hole rules)

- Stop passive when the subdomain set is stable across sources.
- Stop active enum when live hosts are fingerprinted — don't chase the 500th low-value subdomain.
- Stop content discovery on a host once the high-value directories are mapped.
- **Hard rule:** the moment you have one ranked, high-value surface, start hunting it. You can always
  return to recon when a finding opens a new pivot. Mapping is not scoring — bugs are.
