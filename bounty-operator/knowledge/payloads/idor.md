# IDOR / Broken Object-Level Auth

The bug is authorization, not injection: an object reference you can change to reach another tenant's data. **Always prove with two accounts** — attacker (A) requests victim (B)'s object and gets it. One account "editing its own id" proves nothing.

## Setup
Register/hold two accounts. Note B's object ids (order id, user id, file id, invoice id). From A's session, swap in B's references.

## Tier 1 — Id formats to swap
```
GET /api/users/1023/profile        → 1024, 1022, 1          # sequential int
GET /orders/ORD-2024-00815         → ...00814, ...00816     # prefixed serial
GET /files?id=8f3a...              # hash — see UUID note
POST /account {"account_id": 55}   → 56                     # body param
Cookie: acct=55                    → 56                     # cookie-borne id
X-User-Id: 55                      → 56                     # header-borne id
```
Enumerate email/username too: `?email=victim@x.com`.

## Tier 2 — Encoded / wrapped ids
Decode, edit, re-encode. Many "opaque" ids are trivially reversible.
```
base64:   MTAyMw==  → decode 1023 → change → MTAyNA==
hex:       0x3ff → 0x400
double-encoded / URL-encoded id
JSON-wrapped:  {"data":{"id":"1023"}}   swap inner
GraphQL global id:  base64("User:1023")  → base64("User:1024")
MongoID:  652f... timestamp/counter is partly predictable
```

## UUID note
A random v4 UUID resists guessing — but IDOR still lives if the id **leaks**: search results, autocomplete, `include=`, referer, email links, other users' public profiles, error messages, or a list endpoint that returns others' UUIDs. Harvest the victim UUID from one endpoint, replay it at a sensitive one. UUID ≠ safe; it just moves the bug to disclosure + replay.

## Tier 3 — Method & parameter-pollution variants
Same object, different verb/shape often skips the auth check.
```
GET blocked → try POST / PUT / PATCH / DELETE on same path
Wrap as array:      id=1023&id=1024      or   {"id":[1023,1024]}
Duplicate param:    ?id=OWN&id=VICTIM    (server trusts last/first)
Path vs query:      /api/v1/users/1024   vs   /api/user?id=1024   (different guards)
Add trailing:       /users/1024/  ,  /users/1024.json  ,  /users/1024;.css
Mass-assignment:    add {"role":"admin"} / {"owner_id":OTHER} to an update body
Version pivot:      /api/v2 guarded, /api/v1 or /internal not
```
Also: swap tenant/org id (`?org=`) not just user id — often higher impact.

## Stop when
Two-account proof captured: A's authenticated request returns or mutates B's object, side by side with B's own view confirming it's the same object. Screenshot both requests + the leaked field (name/email/order). Touch exactly one victim record to demonstrate — no bulk enumeration, no scripting through the id space. That's your report. Stop.
