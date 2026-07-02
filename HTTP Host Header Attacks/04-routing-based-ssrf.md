# Routing-based SSRF

**Category:** HTTP Host Header Attacks
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/host-header/exploiting/lab-host-header-routing-based-ssrf

Cloud-era architectures put a reverse proxy or load balancer in front of almost everything, and that
component often makes its routing decision using nothing more than the Host header on the incoming
request. That's an efficient design and a dangerous one at the same time — the proxy sits in a
privileged network position with a path into the internal network, and if it trusts the client's
Host header to decide where to forward a request, the client effectively gets to pick the
destination.

## The Target

A normal `GET /` succeeds. The interesting question is what the layer in front of the application
does when the Host header points somewhere other than the public domain — specifically, whether it
forwards the request to whatever it finds at that address rather than only ever forwarding to the
one backend it's meant to serve.

## The Investigation

Before touching the Host header at all, we confirmed a session cookie was required for any of this
to work — probing with a modified Host and no cookies returned 403 regardless of what the header
said, which would have looked identical to "not vulnerable" if we hadn't already picked up cookies
from a normal homepage visit first.

With cookies in place, the response codes for different Host values told a clear story:

- **504 Gateway Timeout** — the proxy accepted the request and tried to route it, but nothing was
  listening at that address. This is actually a positive signal for the vulnerability existing (the
  proxy *did* attempt to route based on our Host header), even though it's a negative signal for
  that specific address having a live backend.
- **302 or 200** — something real answered at that address.

That distinction meant a private-IP sweep wasn't a blind guessing game — every non-504, non-403
response was worth investigating, because it meant the proxy had successfully routed us to a live
internal service.

## The Exploit

We scanned the entire `192.168.0.0/24` range concurrently (20 worker threads), sending `GET /` with
`Host` set to each candidate IP and the session cookies attached:

```
GET /
Host: 192.168.0.X
Cookie: <session cookies>
```

One IP came back with something other than 504 or 403 — a live internal admin panel. Requesting it
directly:

```
GET /admin
Host: 192.168.0.X
Cookie: <session cookies>
```

returned the admin panel along with a CSRF token, extracted via regex from the response body.
Finishing the lab meant reusing that IP and token in a delete request:

```
POST /admin/delete
Host: 192.168.0.X
Cookie: <session cookies>
Body: username=carlos&csrf=<token>
```

which deleted `carlos` and solved the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution opens with a confirmation step we skipped: insert a Burp Collaborator payload
as the Host header value and poll Collaborator for an interaction, proving the middleware really
does issue outbound requests based on an arbitrary Host before spending any effort on the internal
sweep. From there it uses Burp Intruder with "Update Host header to match target" deselected and a
numeric payload against the final octet of `192.168.0.§0§`, sorting results by status code to spot
the one `302` redirecting to `/admin`. The rest — extracting the CSRF token, copying the session
cookie from the admin response, converting the request to `POST` for the delete — matches our
approach exactly.

The real difference is the sweep mechanism, and it's a direct translation rather than a divergence:
Intruder's numeric payload attack over 256 requests is the GUI equivalent of our
`ThreadPoolExecutor`-driven scan over the same range. Both approaches are doing the identical
thing — enumerate every host in the /24 and watch for a response that isn't 504 — just with
different tooling issuing the requests. We also didn't do the standalone Collaborator confirmation
step; going straight to the full sweep meant we found the working IP without a separate step to
prove the primitive existed first, at the cost of not having that isolated confirmation on record.

## What This Teaches Us

This lab demonstrates why routing infrastructure deserves the same scrutiny as application code:
the proxy here was doing exactly what proxies are designed to do — forward a request based on a
Host header — but doing it without validating that the header was one of a small set of legitimate
backends. The 192.168.0.0/24 range wasn't a lucky guess; it's the address space most cloud and
container platforms hand out to internal services by default, which makes it the first thing worth
scanning whenever a Host-header-driven proxy is confirmed. The fix is an allow-list: routing
components that make forwarding decisions from client-supplied headers need to validate those
headers against a fixed set of known-good destinations, not trust whatever the client sends.
