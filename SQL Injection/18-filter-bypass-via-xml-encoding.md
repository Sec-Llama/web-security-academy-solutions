# SQL injection with filter bypass via XML encoding

**Category:** SQL Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding

Every lab in this series so far assumed the injection point itself was the only obstacle. This one
adds a second layer: a web application firewall watching for exactly the keywords a SQL injection
payload needs — `UNION`, `SELECT` — sitting in front of an endpoint that's otherwise injectable in
the ordinary way. The interesting part isn't the SQL. It's what the WAF actually inspects versus
what the application actually executes, and the gap between those two things.

## The Target

A stock-check feature that accepts an XML body:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

The `storeId` value is concatenated into a SQL query server-side — confirmed by sending arithmetic
expressions like `1+1` and observing the response change accordingly. A direct `UNION SELECT`
attempt, though, gets blocked outright: the request never reaches the application at all once it
contains recognizable SQL keywords.

## The Investigation

The key fact this lab is built around is a processing-order mismatch. The WAF inspects the request
body as it arrives on the wire — raw bytes, before any XML processing happens. The application's
XML parser, on the other hand, decodes character entities *before* handing the resulting string to
the SQL layer. Those are two different views of the same request, and a WAF that only looks at the
first one can be shown something completely different from what the database actually receives.

XML supports numeric character references — `&#x53;` for the character `S`, for instance — which
any standards-compliant XML parser resolves automatically as part of normal parsing. If we encode
every character of the injection payload this way, the WAF sees a string with no `UNION`, no
`SELECT`, no recognizable SQL syntax anywhere in it — just a wall of `&#xNN;` entities that happen
to be completely unremarkable, valid XML. The application's parser decodes that same string back
into plain SQL before it ever reaches the query, at which point the WAF has already let it through.

The one implementation detail that mattered here was encoding *every* character of the payload, not
just the keywords. Partial encoding — leaving spaces or punctuation in plaintext — left enough of
a recognizable fragment for some WAF configurations to still flag. Encoding the entire injected
string uniformly removed any plaintext substring for a keyword-matching filter to catch.

## The Exploit

We built the full injection string first in plain SQL, then hex-entity-encoded every character of
it before placing it in the `storeId` element:

```
Plain injection:   UNION SELECT username||'~'||password FROM users
Encoded (excerpt):  &#x55;&#x4E;&#x49;&#x4F;&#x4E;&#x20;&#x53;&#x45;&#x4C;&#x45;&#x43;&#x54;...
```

Sent as:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>1</productId>
<storeId>1&#x20;&#x55;&#x4E;&#x49;&#x4F;&#x4E;&#x20;&#x53;&#x45;&#x4C;&#x45;&#x43;&#x54;...</storeId>
</stockCheck>
```

The request passed the WAF cleanly — nothing in the raw body resembled SQL — and the XML parser
decoded the entities back into the original `UNION SELECT` statement before it reached the
database. The response came back containing every row from `users`, concatenated as
`username~password` pairs using the same separator technique from the earlier UNION labs in this
series. We picked out the `administrator` row, extracted the password, and logged in to solve the
lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the same conclusion through the same mechanism — encode the
injection as XML character entities so the WAF's keyword inspection never sees plaintext SQL — but
gets there with a different tool. Their walkthrough uses Burp's Hackvertor extension, highlighting
the payload text in Repeater and applying its `hex_entities` (or `dec_entities`) transformation
through a right-click menu, wrapping the injected string in a `<@hex_entities>...</@hex_entities>`
tag that Hackvertor expands into entity-encoded output automatically.

We reached the identical byte-level output — every character of the injection string converted to
its `&#xNN;` form — through a small Python helper that does the same character-by-character hex
encoding Hackvertor performs, rather than a Burp extension. The encoded payload the server actually
receives is the same either way; what differs is whether a Burp extension or a few lines of Python
did the encoding.

## What This Teaches Us

This lab is really a lesson about WAFs and parsers seeing different things from the same bytes,
and it generalizes well beyond XML: any time a security control inspects a request before some
downstream decoding step — URL decoding, XML entity decoding, unicode normalization, base64 — a
payload that looks like nothing to the filter and something meaningful to the actual parser will
get through. A WAF is a genuinely useful layer, but this lab is a clean demonstration of why it's
explicitly a defense-in-depth measure and not a substitute for fixing the injection itself:
parameterized queries mean the decoded `storeId` value is still just a string when it reaches SQL,
regardless of what encoding got it past the filter in front of it.
