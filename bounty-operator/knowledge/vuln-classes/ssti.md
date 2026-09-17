# SSTI

> User input reaches a template engine as *template*, not data. The engine evaluates it — arithmetic first, then object access, then RCE.

## Root cause
The app concatenates user input into a template string and renders it server-side, instead of passing it as a bound variable. The gap: "I'm just interpolating a name/subject into the email template" — but the engine treats `{{...}}`/`${...}`/`<%= %>` as code, and its object model reaches the runtime.

## Where it hides
- Email/notification templates, PDF/report generators, "customize your message", subject/body fields.
- Rendered user config: display names, page titles, custom error pages, CMS/wiki blocks, dashboards.
- Server-side rendered search/greeting reflections where the reflection is *evaluated*, not just echoed.
- Frameworks: Jinja2/Flask, Twig/PHP, Freemarker/Java, Velocity, ERB/Rails, Spring EL/Thymeleaf, Handlebars/Node, Smarty, Mako.

## Detection
- Polyglot probe: `${{<%[%'"}}%\`. Then math per syntax: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`, `{{7*'7'}}` (Jinja→`7777777` vs Twig→`49`) to fingerprint the engine.
- `49` back (not `7*7`) = evaluation. Distinguish from XSS: SSTI evaluates *server-side*.
- Confirm engine, then walk its object model. `tplmap` for automation after manual signal.

## Minimum-evidence bar
Server-side **evaluation proven** — arithmetic rendered (`{{7*7}}`→`49`), then, where authorized and non-destructive, a benign command/read (`id`, a controlled OOB callback, reading a non-sensitive env var). Mirror `../../references/validation-gate.md`: a reflected `{{7*7}}` string (unrendered) is not SSTI. Prove evaluation → escalate minimally → stop; don't run destructive commands.

## Depth ladder
1. Confirm evaluation with math; fingerprint the engine.
2. Reach the object model:
   - Jinja2: `{{config}}`, `{{''.__class__.__mro__[1].__subclasses__()}}` → `Popen`/`os` gadget.
   - Twig: `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`.
   - Freemarker: `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}`.
   - ERB: `<%= system("id") %>` / `IO.popen`.
   - Velocity/Spring EL: `''.class.forName('java.lang.Runtime')...`.
3. RCE: spawn a process / OOB callback.
4. Sandbox escape where the engine sandboxes (Jinja2 sandbox bypass via `__globals__`/`__builtins__`).
5. Blind SSTI → OOB (DNS/HTTP) exfil.
6. File read / SSRF via engine primitives when direct RCE is blocked.
See `../payloads/ssti.md` and `../payloads/command-injection.md`.

## Bypass notes
- Filtered `{{`/`}}` → `{%...%}` statement tags, `${...}`, alternate delimiters, attribute-access instead of subscript.
- Blocked keywords (`__class__`, `os`, `system`) → `["__cla"+"ss__"]`, `request|attr("application")...`, hex/unicode, `|attr()` filter chaining.
- Sandbox → reach `__builtins__` via `__globals__` of an allowed function. See `../bypass-tables.md`.

## Chain potential
SSTI → RCE → full server compromise → infra/data. Blind SSTI → OOB → internal recon → SSRF. See `../../references/chaining.md`.

## Real paid example
Real disclosed reports:
- **[Ruby]: Server Side Template Injection** (GitHub Security Lab, $2,300) — hackerone.com/reports/1928279 — SSTI in a Ruby/ERB context reaching the object model.
- **Path traversal, SSTI and RCE on a MailRu acquisition** (Mail.ru, $2,000) — hackerone.com/reports/536130 — SSTI chained with path traversal into full RCE.
- **Server Side Template Injection in Return Magic email templates?** (Shopify, bounty undisclosed) — hackerone.com/reports/423541 — the classic email-template field rendered as a template, not data.
- **Urgent: Server side template injection via Smarty template allows for RCE** (Unikrn, bounty undisclosed) — hackerone.com/reports/164224 — Smarty template field evaluated server-side, escalated to RCE.

**The recurring tell:** the sink is a user-customizable template field (email templates especially), and value comes from proving server-side *evaluation* then walking the engine object model to RCE — reflected `{{7*7}}` alone is not it.

## Rejected variants
- `{{7*7}}` reflected literally (no evaluation) — that's reflected XSS at most.
- Client-side template evaluation only (Angular/Vue sandbox — different class, usually XSS-tier).
- Math evaluates but the engine is fully sandboxed with no reachable escape and no sensitive read.
- Reading only your own template output with no code execution or secret.
