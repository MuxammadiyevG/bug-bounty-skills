# Web Cache Poisoning & Deception

> Poison a shared cache once, serve your payload to everyone (poisoning); or trick the cache into
> storing a victim's private page at a public URL (deception). Mass 0-click on the poisoning side.

## Root cause
- **Poisoning:** the cache key excludes an input that still influences the response. An
  **unkeyed header/param** (`X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Host`, a debug header, a
  fat GET param) changes the cached body, so a poisoned response is served to all later requests on
  that key.
- **Deception:** the cache stores responses based on a **path/extension rule** that misfires — a
  dynamic, authenticated page requested as `/account.css` or `/profile/nonexistent.js` gets cached as
  a "static" asset, and the next visitor reads the previous user's private data.

## Where it hides
- CDN / reverse-proxy / Varnish / Cloudflare / Fastly in front of the app.
- Responses that reflect a header into HTML/JS (`Host`-based links, `X-Forwarded-Host` in canonicals,
  Open Graph, script `src`), or reflect a param.
- Routes with cache rules keyed by extension/path prefix (`*.css`, `/static/*`).
- Redirect responses whose `Location` is header-derived.

## Detection
- Add a cache buster (`?cb=random`) to avoid poisoning real users while testing.
- Probe unkeyed inputs one at a time: send `X-Forwarded-Host: canary.oob`, look for reflection in the
  body/`Location`, then confirm it's **cached** (repeat *without* the header, buster held constant).
- Read cache headers: `Age`, `X-Cache: HIT/MISS`, `Cache-Control`, `Vary` — `Vary` tells you what's
  keyed; anything influential and absent from it is a candidate.
- Deception: request an authenticated page with a static-looking suffix; check if a second (fresh)
  session gets a HIT of your private content.

## Minimum-evidence bar
Poisoning: a malicious response (executing XSS, attacker-controlled redirect, resource swap) served
from cache to a request that did **not** include your injected input — proven with a cache buster so
no real user is affected. Deception: a second session reading the first's private data from cache.
A reflected header that is *not* actually cached is just reflection, not poisoning. Use canaries.

## Depth ladder
1. Find an unkeyed input that reflects.
2. Confirm it's cached (HIT without the input, buster constant).
3. Escalate the reflection: header-based XSS, redirect hijack, or script-src swap → stored, mass 0-click.
4. Deception: cache a private page → cross-user data read.
See `../payloads/xss.md` (for the reflected sink you'll cache) and `../payloads/ssrf.md` (for
`Location`/host-driven redirects).

## Bypass notes
- `Vary` blocking a header → find one *not* in `Vary` that still influences output.
- Normalization stripping your header → try casing, duplicates, or `X-Forwarded-*` family variants.
- Cache only stores certain content-types → target a route that returns that type. See `../bypass-tables.md`.

## Chain potential
Reflected-but-encoded header → harmless alone, but **cached** it becomes stored, mass-served. Pairs
with **HTTP smuggling** to poison keys you can't reach directly. Deception → session/PII read → ATO.
See `../../references/chaining.md`.

## Real paid example
Real disclosed reports:
- **DoS on PayPal via web cache poisoning** (PayPal, $9,700) — hackerone.com/reports/622122 — unkeyed input poisoned the cache to serve a broken response to everyone (weaponized as DoS).
- **Host header web cache poisoning lead to DoS** (Shopify, $2,900) — hackerone.com/reports/1096609 — unkeyed Host header changed the cached body, denying the page to all later visitors.
- **Defacement of catalog.data.gov via web cache poisoning to stored DOMXSS** (GSA Bounty, $750) — hackerone.com/reports/303730 — poisoned an input into cached DOM XSS, mass 0-click.
- **Web cache poisoning attack leads to user information and more** (Postmates, $500) — hackerone.com/reports/492841 — unkeyed input surfaced other users' info from cache.

**The recurring tell:** an input that influences the response but is absent from the cache key (Host / X-Forwarded-Host / a fat param); impact ranges from mass DoS to stored XSS served from cache — always proven with a cache buster, never on real users.

## Rejected variants
- Header reflected but response is `Cache-Control: no-store` / never a HIT — reflection only.
- "Cacheable 200" with no attacker-influenced content difference.
- Deception on a page that's public anyway — no private data crosses users.
- Poisoning demonstrated by affecting real production users instead of a buster/canary.
