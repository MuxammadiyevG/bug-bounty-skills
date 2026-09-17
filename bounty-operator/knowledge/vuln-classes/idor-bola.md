# IDOR / BOLA / BFLA / BOPLA

> The server trusts a client-supplied identifier and returns/mutates an object it never re-checked ownership on. Highest-volume paid class on any API.

## Root cause
The developer authenticates the *session* but authorizes nothing per-object. The mental gap: "the user reached this handler, so the id in the URL must be theirs." Object-level (BOLA), function-level (BFLA — role/endpoint not enforced), and property-level (BOPLA — mass assignment / over-return of fields) are the same mistake at different granularities.

## Where it hides
- REST paths with an id: `/api/users/{id}`, `/orders/{uuid}`, `/documents/{id}/download`.
- Body/query params: `user_id`, `account`, `org`, `tenant`, `file`, `ref`, `parent_id`.
- Multi-tenant SaaS: any `org_id`/`workspace`/`team` boundary — cross-tenant pays double.
- Admin/staff routes reachable by a normal role (BFLA): `/admin/*`, `/internal/*`, verb swaps.
- JSON bodies where you can *add* fields (`role`, `is_admin`, `verified`, `price`) — BOPLA.
- GraphQL node/`node(id:)` resolvers, batch/alias queries.

## Detection
Run every action with **two accounts you control** (A, B). Capture A's request, replay it swapping the object id for B's. Compare bodies. Differentials, not status:
- Sequential/int ids → enumerate a small window. UUIDs → look for a leak source (list endpoints, other responses, referers) before assuming safe.
- Diff the two responses byte-for-byte — a `403` on read but `200` on `/refund` is BFLA.
- Add unexpected fields to writes to test mass assignment. Compare returned object.
- `arjun`/`param-discover` for hidden authz params. Sort by nouns that name objects.

## Minimum-evidence bar
B's **actual data returned in A's session** (or B's object mutated by A) — a field only B could have: their email, their document body, their balance. Two accounts you own. Mirror `../../references/validation-gate.md`: not a 200, not a reflected id, not a hung request. Prove with one record, one field — then stop. Never bulk-enumerate real users.

## Depth ladder
1. Swap the id (int/UUID) on the read endpoint; confirm cross-user body.
2. Find the matching **write/delete** IDOR — modify pays more than read.
3. Cross-tenant: swap `org_id`/`workspace` — SaaS multiplier.
4. BFLA: replay a privileged action as low-priv; swap HTTP verb (`GET`→`PUT`/`DELETE`), swap content-type.
5. BOPLA: inject `role`/`is_admin`/`price`/`status` into create/update bodies (mass assignment).
6. Nested/indirect: id in JWT/cookie, in a base64 blob, in a second request of a flow; wrapper objects (`{"user":{"id":..}}`).
7. Chain enumeration into mass read only to *prove scale* conceptually — then stop. See `../payloads/idor.md`.

## Bypass notes
- Filter on `?id=` → move it to a header, JSON body, or path segment.
- id normalization: try `123`, `123.0`, `0123`, `123%00`, array `id[]=123&id[]=456`, wrapped `{"id":["self","victim"]}`.
- Encoded/hashed ids → decode (base64, hex), predict, or find the plaintext leak.
- 403 wall → path/case/verb tricks in `../bypass-tables.md`; trailing `/`, `;`, `%2e`, double URL-encode.

## Chain potential
Read IDOR → enumerate → mass PII. Read → leak a token/reset link → **ATO**. Write IDOR → change victim email/role → **ATO / priv-esc**. BFLA on billing → financial impact. See `../../references/chaining.md`.

## Real paid example
Real disclosed reports:
- **IDOR to add secondary users in www.paypal.com/businessmanage/users/api/v1/users** (PayPal, $10,500) — hackerone.com/reports/415081 — the user-management API trusted a client-supplied account id, letting an attacker add secondary users to any business account (write BFLA, not just read).
- **An IDOR that can lead to enumeration of a user and disclosure of email and phone number within cashier** (Unikrn, $3,000) — hackerone.com/reports/1966006 — a cashier object id enumerated real users and leaked email + phone; sensitive PII returned in the attacker's session.
- **idor allows you to delete photos and album from a gallery** (Pornhub, $1,500) — hackerone.com/reports/380410 — a delete endpoint keyed on a guessable photo/album id with no ownership check — destructive write IDOR.
- **[Razer Pay Mobile App] Broken Access Control Allowing Other User's Bank Account Deletion** (Razer, $1,000) — hackerone.com/reports/757095 — a mobile-API id let one user delete another's bank account; classic BOLA on a mutating call.

**The recurring tell:** every one authenticates the session but never re-checks that the id in the path/body belongs to the caller — and the biggest payouts are on the *write/delete* variant (add user, delete account, delete album), not read.

## Rejected variants
- Reflecting your *own* id back (reading your own data).
- 200 with no other-user data in the body.
- "Sequential ids exist" with no successful cross-user fetch.
- Publicly-shared-by-design resources (public profiles, share links working as intended).
- Enumeration of non-sensitive objects (public blog post ids).
