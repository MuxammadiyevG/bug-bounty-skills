# Nuclei Workflow — scanner as map, not as hunter

> Nuclei is the most effective automated vulnerability scanner in bug bounty — but only when used
> to surface anomalies for manual follow-up, not as a fire-and-forget payload cannon. This file
> covers: template sources, effective usage patterns, custom template writing, and integration
> with the bounty-operator workflow.

## Core principle

Nuclei finds known patterns fast. It does **not** find business-logic bugs, authorization flaws,
or novel vulnerabilities. Use it to map the territory, then walk into the corners by hand.

```
nuclei output → anomalies → manual investigation → real findings
```

A nuclei hit is a *lead*, not a finding. Always verify manually before logging to the ledger.

---

## Template sources (priority order)

1. **projectdiscovery/nuclei-templates** — the official set; always keep updated.
   ```bash
   nuclei -update-templates
   ```

2. **projectdiscovery/fuzzing-templates** — active fuzzing templates (param-based, header-based).

3. **Community collections** — 300+ repos curated at `emadshanab/Nuclei-Templates-Collection`.
   Clone selectively (not all at once — many overlap):
   ```bash
   # High-signal community sets worth cloning:
   # 0xKayala/Custom-Nuclei-Templates — practical, maintained
   # daffainfo/my-nuclei-templates — solid CVE + misconfig coverage
   # esetal/nuclei-bb-templates — bug-bounty-focused
   # h0tak88r/nuclei_templates — well-curated
   # pikpikcu/nuclei-templates — broad CVE coverage
   # KeepHowling/all_freaking_nuclei_templates — massive merged set
   ```

4. **Your own custom templates** — the highest-value source. Write templates for patterns you
   find repeatedly on your targets (see "Writing custom templates" below).

---

## Effective usage patterns

### Phase 3 integration (active recon — after fingerprinting)

```bash
# HIGH-signal sweep: critical + high severity only, against fingerprinted hosts
nuclei -l live_hosts.txt -severity critical,high -o findings_critical.txt

# Technology-specific: run only templates matching the fingerprinted stack
nuclei -l live_hosts.txt -tags apache,nginx,wordpress,spring -o findings_tech.txt

# Exposure check: misconfigs, default creds, sensitive files
nuclei -l live_hosts.txt -tags exposure,misconfig,default-login -o findings_exposure.txt
```

### Targeted scans (after system modeling — phase 4/5)

```bash
# CVE scan against specific fingerprinted versions
nuclei -u https://target.com -tags cve -severity critical,high

# Auth-related templates (feeds into BOLA/BFLA hunting)
nuclei -l live_hosts.txt -tags auth-bypass,default-login,token

# JS and secret exposure
nuclei -l live_hosts.txt -tags exposure,token,secret,js

# Fuzzing specific parameters (after param discovery)
nuclei -l urls_with_params.txt -t fuzzing-templates/ -type http
```

### What NOT to do

- Don't run `nuclei -l hosts.txt` with all templates against every host — too noisy, too slow.
- Don't treat a nuclei "confirmed" as a finding without manual verification.
- Don't skip nuclei because "it only finds known stuff" — it finds the known stuff *fast*, freeing
  you to hunt the unknown.
- Don't run nuclei before fingerprinting — technology-targeted scans have 10x signal-to-noise.

---

## Writing custom templates

The highest-value templates are ones **you** write for patterns you see repeatedly. A custom
template turns a manual 5-minute check into a 5-second automated one across your entire scope.

Template structure (YAML):
```yaml
id: custom-sensitive-api-exposure
info:
  name: Sensitive API endpoint exposure
  author: your-handle
  severity: high
  description: Detects exposed sensitive API endpoints
  tags: custom,exposure,api

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/v1/admin/users"
      - "{{BaseURL}}/api/internal/config"
      - "{{BaseURL}}/graphql?query={__schema{types{name}}}"
    matchers-condition: or
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["email", "password", "admin", "secret"]
        condition: or
```

Good candidates for custom templates:
- Exposed admin/debug/internal endpoints you keep finding
- Specific CMS/framework misconfigs for your target's stack
- Default credential patterns for services in your scope
- Information disclosure patterns (stack traces, version strings, internal IPs)
- Technology-specific misconfigurations (Spring Actuator, Laravel debug, Next.js middleware)

---

## Integration with coverage ledger

Log nuclei results that lead to manual findings:

```bash
# After nuclei finds something interesting and you verify manually:
python3 scripts/ledger.py add --target acme.com \
    --surface "/actuator/env" --class info-disclosure \
    --hypothesis "Spring Actuator env endpoint exposed" \
    --result confirmed --fid F-023

# If nuclei hit is a false positive after manual check:
python3 scripts/ledger.py add --target acme.com \
    --surface "/api/v1/health" --class info-disclosure \
    --result killed --why "health endpoint returns no sensitive data; public by design"
```

## Template management

```bash
# Update official templates
nuclei -update-templates

# Use custom templates alongside official ones
nuclei -l hosts.txt -t ~/nuclei-templates/ -t ~/custom-templates/ -severity critical,high

# List available tags for targeted scanning
nuclei -tl -tags | sort | uniq -c | sort -rn | head -20
```
