# GraphQL

> One endpoint, many resolvers — and authz is per-field, so it's routinely enforced unevenly. Introspection hands you the whole attack surface for free.

## Root cause
The schema centralizes data access but authorization is decentralized to each resolver, so some fields/mutations are left unguarded. The gap: "the top-level query is protected" — but a nested field, an alias, or a sibling mutation reaches the same object without the check.

## Where it hides
- `/graphql`, `/api/graphql`, `/graphql/console`, `/v1/graphql`, `/gql`, Hasura/Apollo/Relay endpoints.
- Nested resolvers: `me { organization { members { email } } }` — the boundary breaks deep in the tree.
- Mutations that mirror REST IDOR (`updateUser`, `deleteNode`, `node(id:)`).
- Batching (array of queries / aliased queries) — bypasses per-request rate limits.
- Arguments passed to backend queries → injection (SQL/NoSQL) via GraphQL variables.

## Detection
- Introspection: `{__schema{types{name fields{name}}}}` — dump the full schema. If disabled, use field-suggestion (clairvoyance) errors to reconstruct it.
- Fingerprint the engine (`graphw00f`); run `graphql-cop`/`inql` for quick misconfig triage.
- Map every query/mutation; test authz on each with two accounts.
- Alias the same field N times to test batching/rate-limit and IDOR-via-alias.

## Minimum-evidence bar
Same discipline as the underlying class. IDOR-via-GraphQL → **another user's data in the response body** (two accounts). Injection → boolean/time/OOB proof. Batching DoS → a measured resource/time blowup that maps to real denial (only where DoS is in scope). Mirror `../../references/validation-gate.md`: introspection being enabled is *informative* on its own — chain it to a real read/mutation.

## Depth ladder
1. Introspect (or clairvoyance) → full schema map.
2. Aliasing IDOR: `a: user(id:1){email} b: user(id:2){email}` — batch-enumerate other users in one request.
3. Nested-authz bypass: reach a protected object through an unguarded parent/child field.
4. BFLA: call an admin/privileged mutation as a low-priv user.
5. Injection via arguments/variables → SQL/NoSQL (see `../payloads/sqli.md`, `../payloads/nosqli.md`).
6. Batching/depth/complexity DoS: deeply nested or N-aliased query (where in scope).
7. Subscription abuse / CSRF on GET-based GraphQL.
8. Field-level over-return (BOPLA): request sensitive fields (`passwordHash`, `token`) the UI never asks for.

## Bypass notes
- Introspection disabled → field suggestions ("Did you mean...") leak names; POST vs GET vs `application/graphql` content-type may re-enable it.
- Query allow-list / persisted queries → try the non-persisted path, alias tricks, operation-name confusion.
- Rate limit per request → batch many operations in one request (aliases/array).
- WAF on query string → move to POST body / variables. See `../bypass-tables.md`.

## Chain potential
Introspection → hidden mutation → IDOR/BFLA → cross-tenant data or priv-esc. Aliasing IDOR → mass PII. Argument injection → SQLi → DB. See `../../references/chaining.md`.

## Real paid example
`user(id:)` resolver enforced auth only at the top level; the `organization { billingEmail }` nested field returned any org's billing contact regardless of membership. Aliased 50 org ids in one request to prove scale (stopped after 2). Cross-tenant PII. Band: **$2k–$8k**.

## Rejected variants
- Introspection enabled, full stop — no sensitive query/mutation reached.
- "Verbose errors" / suggestions with no data impact.
- Depth/complexity "DoS" theory with no measured impact and DoS out of scope.
- Reading your own objects via GraphQL.
- Deprecated-field disclosure with no secret.
