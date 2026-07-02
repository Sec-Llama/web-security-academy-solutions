# Authentication bypass via information disclosure

**Category:** Information Disclosure
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-authentication-bypass

Reverse proxies routinely enrich requests before forwarding them upstream — adding headers that
tell the backend things like the client's real IP address, since the backend only ever sees the
proxy's own connection. That's a reasonable design, right up until the mechanism for deciding
"is this an internal admin request" leaks its own name in a diagnostic response. This lab turns an
HTTP method almost nobody uses on purpose — `TRACE` — into a full authentication bypass.

## The Target

The application has an admin panel at `/admin` that's restricted to requests coming from
localhost — the kind of "internal only" access control that's common for admin interfaces sitting
behind a reverse proxy, on the assumption that only the proxy itself, or something on the same
host, could ever appear to originate from `127.0.0.1`.

## The Investigation

`TRACE` is a diagnostic HTTP method that, when enabled, makes the server echo the exact request it
received back in the response body — headers and all, including any headers a proxy in front of it
added before the request reached the origin server. That makes it a direct window into
request-enrichment logic that's otherwise completely invisible to a client. We sent:

```
TRACE /admin HTTP/1.1
```

The response echoed the request back, and among the headers was one we hadn't sent ourselves:

```
X-Custom-IP-Authorization: <our IP>
```

That's the whole bypass sitting in plain sight — a reverse proxy was appending this header with the
client's real IP address, and the backend almost certainly trusts it as the source of truth for the
"is this request from localhost" check, rather than looking at the actual TCP connection. Our
detector generalizes this: it scans the echoed `TRACE` response for any `X-*` header and
preferentially selects ones whose name contains `ip`, `forward`, or `auth` — since those are the
header families reverse proxies typically use for this kind of enrichment.

## The Exploit

With the header name in hand, we sent a normal `GET /admin` request, this time supplying the
discovered header ourselves and spoofing it to localhost:

```
GET /admin HTTP/1.1
X-Custom-IP-Authorization: 127.0.0.1
```

The backend trusted our self-supplied header over the actual connection source, and the response
was the full admin panel — access control bypassed entirely by lying about a header the proxy was
supposed to be the only one allowed to set. From there, the admin panel exposed a delete link for
the user `carlos`. We extracted that link and requested it with the same spoofed header attached:

```
GET /admin/delete?username=carlos HTTP/1.1
X-Custom-IP-Authorization: 127.0.0.1
```

The lab tracker confirmed the solve once `carlos` was deleted.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger reaches the same header name through the same `TRACE /admin` request, and the same
observation that the admin panel is IP-restricted in a way that a spoofable header controls. Their
walkthrough sets up the spoofed header differently in mechanics, though functionally to the same
effect: rather than adding the header to individual requests, they configure Burp Proxy's
**Match and replace** rule to inject `X-Custom-IP-Authorization: 127.0.0.1` into every outgoing
request automatically, then simply browse to the admin panel through the browser as normal — the
proxy handles the header transparently from that point on.

Our script takes the more direct route for a scripted exploit: since we're not routing traffic
through an interception proxy at all, we just attach the header explicitly to the two requests that
actually need it (the admin panel fetch and the delete request), rather than configuring a
persistent rule that applies to all traffic. Same header, same value, same bypass — the difference
is whether the header gets attached once as a global proxy rule or per-request in code.

## What This Teaches Us

The underlying mistake is trusting a client-controllable value — an HTTP header — as if it were an
unforgeable fact about the network path. `X-Custom-IP-Authorization` was meant to carry information
*the proxy* asserted about the client, but nothing at the backend enforced that the header could
only arrive from the proxy; a client could set the exact same header directly and get the exact
same trust. This is a broader pattern worth generalizing beyond this one lab: any header whose name
suggests it carries a security decision (IP address, role, "internal" flag) needs to be stripped
from incoming requests at the perimeter and only re-added by infrastructure the backend actually
trusts — never left as a header name a client can simply guess or, as here, discover for free
through a diagnostic HTTP method that should have been disabled in the first place.
