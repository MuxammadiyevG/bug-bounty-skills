# NoSQL Injection

> Operator injection into document stores (MongoDB, CouchDB, Firebase-style query layers). Pays because it turns a login form into an auth bypass and a filter param into cross-tenant read.

## Root cause
User input reaches a query object without type enforcement. JSON bodies let an attacker send an
object where the app expected a string, so `{"user":"admin","pass":"x"}` becomes
`{"user":"admin","pass":{"$ne":"x"}}`. The driver treats the object as a query operator, not a value.
Same failure in URL-encoded form: `user[$ne]=` parses to a nested object in Express/PHP. Comparison,
evaluation (`$where`, `$regex`, `$expr`), and projection operators all become attacker-controlled.

## Where it hides
- Login / auth endpoints that build `findOne({user, pass})` straight from the body.
- Search, filter, sort, and pagination params (`?sort[$where]=...`).
- GraphQL resolvers that forward client-supplied filter objects into Mongo verbatim.
- Password-reset token lookups (`{token: userInput}` → `{token:{$ne:null}}` returns the first row).
- Aggregation pipelines built from user JSON.
- Any endpoint parsing `application/json` OR nested-bracket form syntax into the query.

## Detection
- Swap a string value for `{"$ne":null}` / `{"$gt":""}` and watch for a behavioral flip
  (login succeeds, list returns more rows, a 401 becomes a 200 *with a real body*).
- Boolean-differential with `$regex`: `{"$regex":"^a"}` vs `{"$regex":"^z"}` — different responses
  means you can extract a value char by char.
- Time-based via `$where`/`$function` (JS eval): inject a sleep and measure. Confirms eval context.
- Send both encodings: JSON body objects and `param[$ne]=1` bracket form; frameworks differ.

## Minimum-evidence bar
Auth bypass: you land inside an account/state you do not own, shown in the response body — not a 200
alone. Data extraction: the *other* tenant's or user's actual document field returned, or a
boolean/time oracle that provably reads a secret (extract one field, then stop). A reflected operator
that changes a status code without a real body is not proof. Never dump the collection.

## Depth ladder
1. Confirm operator injection (`$ne`/`$gt` behavioral flip).
2. Auth bypass on login / reset-token lookup.
3. Blind extraction with `$regex` anchors — pull one credential/hash to prove read.
4. `$where` / `$function` server-side JS → command context on old MongoDB or misconfigured eval.
See `../payloads/nosqli.md` for operator and encoding payloads.

## Bypass notes
- WAF filtering `$`? Try bracket-form, unicode-escaped keys in JSON, or `$` in a nested array.
- App rejects objects on one content-type — resend as the other (JSON ↔ form ↔ query string).
- `$regex` DoS-heavy filters blocked → fall back to `$gt`/`$lt` binary search on ordered fields.
See `../bypass-tables.md`.

## Chain potential
Auth bypass → land as admin → BFLA on admin functions. Blind read → pull a reset token or session →
ATO. `$where` JS eval → RCE candidate on the DB host. See `../../references/chaining.md`.

## Real paid example
A SaaS login accepted a JSON body. Sending `{"email":"admin@target.tld","password":{"$gt":""}}`
authenticated as the named admin because the handler passed the object straight to `findOne`. Proven
by reaching the admin dashboard as a user with no credentials. Auth bypass on the primary product,
no interaction, pre-auth. Rough band: $4k–$12k.

## Rejected variants
- Operator reflected but query is parameterized/typed — no behavioral change. Not a bug.
- Error message mentions Mongo but input is coerced to string before the query.
- `$ne` flips a status code with an empty/error body and no state change — anomaly, not impact.
- Injection into your own document only (self-scoped) with no cross-user or auth effect.
