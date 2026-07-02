# Web cache poisoning via HTTP/2 request tunnelling

**Category:** HTTP Request Smuggling
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/request-smuggling/advanced/request-tunnelling/lab-request-smuggling-h2-web-cache-poisoning-via-request-tunnelling

The previous tunnelling lab hid a second request inside a header name to leak and forge authentication headers. This one hides a second request inside the `:path` pseudo-header — HTTP/2's third distinct CRLF injection surface — and chains it into a cache-poisoning XSS that persists across every visitor until the cache entry is overwritten.

## The Target

Same connection-reuse-averse front-end as the access-control tunnelling lab, so no classic connection-poisoning smuggling is available here either. The relevant gadget is a redirect: `GET /resources` (no trailing slash) returns a 302 to `/resources/`, and — as in the earlier CL.TE cache poisoning lab — the redirect's `Location` header reflects request content without HTML-encoding it, because it's generated as an HTTP header value, not rendered HTML.

## The Investigation

The `:path` pseudo-header is a third distinct CRLF injection vector alongside header names and header values, and front-ends that sanitize both of the others don't necessarily extend that sanitization to `:path` — it's syntactically a path, not a "header," so it's easy for a downgrade implementation to treat it as exempt from header-injection defenses. We confirmed the injection first with a low-stakes probe that preserved a valid request line after the split:

```
:path = /?cachebuster=1 HTTP/1.1\r\nFoo: bar
```

A normal response confirmed the injection landed without breaking the request. From there, changing the method to `HEAD` and extending the `:path` value to include a complete second request turns this into non-blind tunnelling: `HEAD` responses have a `Content-Length` but no body of their own, so if the front-end over-reads based on that declared length, whatever the *tunnelled* request's response contains leaks back into the space that should have been empty.

```
:path = / HTTP/1.1\r\nHost: TARGET\r\n\r\nGET /post?postId=1 HTTP/1.1\r\nFoo: bar
```

Making this work with the Python `h2` library required one more fix beyond the usual disabled header validation: the library independently validates that a response body's actual length matches its declared `Content-Length`, and a `HEAD` response that unexpectedly carries tunnelled body data trips that check and raises an error before we ever get to read the data. Patching around it meant disabling the library's own content-length tracking for the stream: `h2.stream.H2Stream._track_content_length = lambda self, *args: None`. Without that patch, the library actively prevented us from reading the exact response data the attack depends on.

With tunnelling confirmed, we retargeted the tunnelled request at `/resources`, embedding an XSS payload directly in its query string:

```
:path = / HTTP/1.1\r\nHost: TARGET\r\n\r\nGET /resources?<script>alert(1)</script>PADDING HTTP/1.1\r\nFoo: bar
```

The tunnelled `/resources` request produces a 302 whose `Location` header reflects that query string verbatim, unencoded. The catch is that the outer `HEAD /` response's `Content-Length` is fixed at the size of the real home page, and our tunnelled 302 response has to be *at least* that long or the front-end times out waiting for bytes that never arrive — so the XSS payload needed several thousand characters of padding appended after the closing `</script>` tag purely to satisfy that length requirement.

## The Exploit

```
:method: HEAD
:path: / HTTP/1.1\r\nHost: TARGET\r\n\r\nGET /resources?<script>alert(1)</script>PADDING HTTP/1.1\r\nFoo: bar
:authority: TARGET
```

with roughly 8,500 characters of padding appended after the script tag to exceed the home page's `Content-Length`. Sending this returns the tunnelled 302 response, containing our unencoded `<script>` payload in its `Location` header, nested inside the outer `HEAD /` response body. Because the front-end reads exactly `Content-Length` bytes and treats whatever it receives as the cacheable body for `/`, it caches our raw HTTP response text — script tag included — as the content of the home page itself. Once the cache held that poisoned entry, browsing to `/` in a normal browser rendered the raw response as `text/html` and executed the embedded script. We resent the tunnelling request roughly every five seconds to keep the cache poisoned against its TTL until the lab's simulated visitor loaded the home page and triggered the alert.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution builds the identical chain — confirm `:path` injection, escalate to `HEAD`-based non-blind tunnelling, find the `/resources` redirect gadget, pad the tunnelled response past the outer `Content-Length`, then poison and sustain the cache:

```
:path
/?cachebuster=3 HTTP/1.1\r\n
Host: YOUR-LAB-ID.web-security-academy.net\r\n
\r\n
GET /resources?alert(1) HTTP/1.1\r\n
Foo: bar
```

with the same explicit padding step once a timeout confirms the tunnelled response is too short, and the same "keep resending every 5 seconds until the victim visits" sustain loop we ran. The technique matches ours exactly, non-blind `HEAD` tunnelling via `:path` injection is essentially the only route to this particular XSS-via-cache-poisoning outcome given the constraints of this lab. Where our paths genuinely diverged was purely in implementation plumbing: Burp's HTTP/2 tooling doesn't need to work around content-length validation the way a general-purpose `h2` client does, since Burp's own HTTP/2 stack was built with exactly this kind of protocol-violating request in mind, whereas we had to patch the `h2` library's internal stream-tracking behavior to even read the tunnelled data back without it raising an error first.

## What This Teaches Us

This lab closes out the tunnelling techniques by showing all three CRLF injection surfaces — header value, header name, and now `:path` — converging on the same underlying failure: a downgrade implementation that treats different parts of an HTTP/2 request as having different levels of trustworthiness, when an attacker who controls one almost certainly controls all three. It's also a reminder that content-length-based response boundaries cut both ways as an attack surface: the same mechanism that lets a `HEAD` response "know" how much data follows is exactly what lets an over-length tunnelled response leak past it, provided the attacker can pad their way past the declared boundary.
