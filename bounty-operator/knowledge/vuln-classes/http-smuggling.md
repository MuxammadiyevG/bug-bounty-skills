# HTTP Request Smuggling

> A front-end and back-end disagree on where one request ends. You prepend bytes onto the next
> user's request. CL.TE / TE.CL / H2.CL. Mass 0-click impact when it lands.

## Root cause
Two servers in a chain (CDN/proxy/load balancer → origin) parse message length differently.
Discrepancy sources: one honors `Content-Length`, the other `Transfer-Encoding: chunked`
(**CL.TE / TE.CL**); or an HTTP/2 front-end downgrades to HTTP/1.1 and the origin trusts a smuggled
`Content-Length`/`Transfer-Encoding` from the h2 body (**H2.CL / H2.TE**). The "extra" bytes sit in
the back-end buffer and get glued to the front of the next request on that reused connection.

## Where it hides
- Any target behind a CDN/reverse proxy/load balancer (most are).
- Endpoints where front-end and origin are different software/versions.
- HTTP/2 front-ends that downgrade to HTTP/1.1 upstream — check for h2 support then probe H2.CL.
- Keep-alive connections shared across users (the smuggling victim pool).

## Detection
- Timing probe (safe first): a TE.CL/CL.TE differential makes the socket hang for a set time when the
  back-end waits for bytes that never come. Baseline vs. probe delta.
- Then the confirm: send a self-poison where *your own* follow-up request gets the prepended bytes —
  you observe your smuggled prefix reflected, proving the desync without touching other users.
- HTTP/2: send `content-length`/`transfer-encoding` in h2 pseudo/regular headers and watch downgrade
  behavior. Use a tool that speaks raw h2 (the desync is invisible over normal clients).

## Minimum-evidence bar
A confirmed desync you can reproduce, shown via **self-poisoning** — your smuggled prefix lands on a
request you also sent, or a controlled OOB/canary proves the split. A single hung request is not
proof (many things hang). Do **not** poison other users' live traffic to demonstrate; use your own
requests / a benign canary path. State the concrete impact the desync enables.

## Depth ladder
1. Timing differential → suspect desync.
2. Self-poison confirm (your prefix on your next request).
3. Capture *your own* subsequent request's headers (steal-your-own-session style) → proves victim
   request capture is possible without hitting real users.
4. Route smuggled requests to internal-only paths, or poison the shared cache (see cache-poisoning).
See `../payloads/smuggling.md`.

## Bypass notes
- `Transfer-Encoding` obfuscation to slip past one parser: `Transfer-Encoding:\tchunked`,
  duplicate TE headers, `Transfer-Encoding: xchunked`, space before colon, TE in the h2 body.
- CL.0 / H2.0 variants when the origin ignores the body entirely. See `../bypass-tables.md`.

## Chain potential
Desync → **cache poisoning** (mass 0-click) → stored XSS/redirect for every visitor. Desync →
capture victim session/CSRF tokens → ATO. Desync → bypass front-end auth/WAF to reach internal
routes. See `../../references/chaining.md`.

## Real paid example
Real disclosed reports:
- **HTTP Request Smuggling via HTTP/2** (Basecamp, $7,500) — hackerone.com/reports/1211724 — an h2 front-end downgrades and the origin trusts a smuggled length.
- **HTTP request smuggling (?) canpol.deti.mail.ru** (Mail.ru, $5,000) — hackerone.com/reports/957881 — front-end/origin length disagreement confirmed via self-poison.
- **Password theft login.newrelic.com via Request Smuggling** (New Relic, $3,000) — hackerone.com/reports/498052 — desync captures credentials off the shared connection.
- **Mass account takeovers using HTTP Request Smuggling on https://slackb.com/ to steal session cookies** (Slack, bounty undisclosed) — hackerone.com/reports/737140 — desync harvests other users' session cookies at scale.

**The recurring tell:** a CDN/proxy and the origin disagree on where a request ends, so smuggled bytes prepend onto the next connection user's request — the payout tracks straight to captured sessions/credentials and mass 0-click ATO.

## Rejected variants
- A hung request with no reproducible self-poison — timing noise, not a desync.
- Desync against a lab/staging host out of scope.
- "Front-end and origin are the same server" — no parser disagreement, no smuggling.
- Demonstrating impact by poisoning real users' traffic — out of bounds; use self/canary only.
