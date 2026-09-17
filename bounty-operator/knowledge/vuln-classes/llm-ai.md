# LLM / AI Security

> Prompt injection (direct and indirect), chatbot IDOR, data exfiltration, and agentic (tool-using)
> abuse. Pays when the model's actions cross a trust or authorization boundary — not when it just
> says something rude.

## Root cause
The model treats all text in its context as instructions, and the app grants the model authority
(data access, tools, actions) scoped more broadly than the *user* driving it. Two failure families:
- **Instruction/data confusion:** untrusted content (user input, retrieved docs, tool output, a web
  page, a file) is interpreted as commands → **prompt injection**.
- **Broken authorization around the model:** the model or its tools read/write data or invoke
  functions on behalf of a user who shouldn't have that access → **chatbot IDOR / excessive agency**.

## Where it hides
- Chatbots and copilots wired to user data, tickets, orders, or internal APIs.
- RAG pipelines ingesting untrusted documents/webpages (indirect injection).
- Agents with tools: code execution, HTTP fetch, email/DB/file actions, browser use.
- Summarizers of user-supplied content (emails, PDFs, repos, support threads).
- System-prompt / config exposed via the chat surface.

## Detection
- **Direct injection:** "ignore previous instructions" class tests; check whether guardrails,
  system-prompt secrets, or tool scope can be overridden.
- **Indirect injection:** plant instructions in a document/page/field the model will later ingest;
  see if they execute in another user's or a privileged context. ASCII/unicode-smuggled and
  zero-width text bypass naive filters.
- **Chatbot IDOR:** ask the assistant for another user's/tenant's record by id; check if its backend
  tool fetches without scoping to *your* identity.
- **Exfil channels:** markdown image/link auto-render, tool HTTP fetch, or a rendered citation that
  beacons out with data in the URL.

## Minimum-evidence bar
A crossed boundary with real impact: another user's/tenant's actual data returned (chatbot IDOR), a
tool action executed that the driving user isn't authorized for, secret/system-prompt/credential
disclosure that's *usable*, or data exfiltrated to an endpoint you control. A jailbreak that only
makes the model emit disallowed *text* with no data/action boundary crossed is generally not paid.
Prove one crossed boundary (one record, one action, one exfil hit), then stop.

## Depth ladder
1. Direct injection → override guardrail / extract system prompt.
2. Chatbot IDOR → other-user data via the model's tool.
3. Indirect injection → instructions in ingested content fire in a victim/privileged context (0-click).
4. Exfil → route the read data out-of-band (markdown-image beacon / tool fetch).
5. Agentic RCE → injection reaches a code-execution or shell tool → see `../payloads/command-injection.md`.

## The ASI01–ASI10 agentic frame
Walk an agentic target against these: **ASI01** prompt/instruction injection · **ASI02** tool misuse
/ excessive agency · **ASI03** privilege & authorization compromise (agent acts beyond the user) ·
**ASI04** resource / cost exhaustion · **ASI05** supply-chain (tools, plugins, models) · **ASI06**
memory / context poisoning that persists across sessions · **ASI07** untrusted-output handling
(agent trusts tool/model output as commands) · **ASI08** unsafe action execution (side-effecting
tools without confirmation) · **ASI09** identity & trust-boundary failures across agents · **ASI10**
observability/oversight gaps that hide the abuse. Map each finding to one and rate at the crossed
boundary.

## Bypass notes
- Filter on "ignore instructions" → paraphrase, encode, translate, or smuggle via zero-width/unicode.
- Output filters → exfil through markdown rendering or a tool side-effect, not plain text.
- Guardrail model in front → indirect injection via ingested content sidesteps the input filter.
See `../bypass-tables.md`.

## Chain potential
Indirect injection → the agent's authenticated tool → **IDOR/data theft** or **SSRF** (→ cloud
metadata) or **RCE** (code tool). Memory poisoning → persistent cross-session compromise. See
`../../references/chaining.md`.

## Real paid example
A support copilot let users query order status through a backend tool. Asking it for order
`#100438` (not the user's) returned another customer's name, address, and order contents because the
tool fetched by id without scoping to the session identity. Chatbot IDOR (ASI03) proven with one
other-tenant record, then stopped. Rough band: $3k–$12k.

## Rejected variants
- A jailbreak producing disallowed text with no data access, no action, no exfil — content policy, not
  a security boundary.
- The model "hallucinates" a fake secret it never actually had access to.
- System prompt extraction where the prompt contains nothing sensitive or usable.
- Injection that only affects the attacker's own session and own data.
