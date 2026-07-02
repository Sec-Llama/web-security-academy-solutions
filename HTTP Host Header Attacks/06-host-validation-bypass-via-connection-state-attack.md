# Host validation bypass via connection state attack

**Category:** HTTP Host Header Attacks
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/host-header/exploiting/lab-host-header-host-validation-bypass-via-connection-state-attack

HTTP/1.1 connections are frequently reused for several requests in a row, purely for performance —
setting up a fresh TCP and TLS handshake for every request is expensive. That reuse creates a subtle
opportunity: if a front-end only validates the Host header on the *first* request of a connection
and assumes every later request on the same connection is for the same host, then whatever passed
validation once has effectively bought a free pass for the rest of that connection's lifetime.

## The Target

This lab's proxy validates the Host header — a direct request to `/admin` with
`Host: 192.168.0.1` doesn't get routed anywhere useful, it just gets redirected back to the
homepage, unlike the earlier labs where a bad Host header produced a 504 or a 403. Validation here
is clearly happening. The question is whether it's happening on every request, or just once per
connection.

## The Investigation

The lab's target hostname carries an `h1-` prefix, which enforces HTTP/1.1 without ALPN negotiation
— no opportunistic upgrade to HTTP/2, which multiplexes streams differently and wouldn't exhibit the
same connection-reuse assumption in the same way. That detail matters because the whole attack
depends on genuinely keeping one TCP/TLS connection open across two distinct HTTP/1.1 request/response
cycles, with `Connection: keep-alive` on the first request telling the server not to tear the
connection down afterward.

We tested the hypothesis directly: open one connection, send a first request with a legitimate Host
header and `Connection: keep-alive`, read that response, then send a second request down the *same*
socket with `Host: 192.168.0.1` and `Connection: close`. If the front-end validates every request
independently, the second request should be rejected exactly like a fresh request with that Host
would be. It wasn't — the second request went straight through to the internal target, confirming
validation only runs once per connection, on the first request.

One prerequisite we confirmed was easy to miss: session cookies have to be present on *both*
requests, not just the second. Sending the pair without cookies returned 421 Misdirected Request
rather than the expected redirect-then-bypass sequence, which is a different failure mode than the
cookie-related 403s seen in the routing SSRF labs — worth noting as its own distinct signal that
something about the request's authentication state, not just its Host header, was wrong.

## The Exploit

Our script implements the two-request sequence over a single raw TLS socket:

```
Request 1 (same connection): GET / HTTP/1.1
Host: <legitimate lab domain>
Cookie: <session cookies>
Connection: keep-alive

Request 2 (same connection): GET /admin HTTP/1.1
Host: 192.168.0.1
Cookie: <session cookies>
Connection: close
```

The second response came back as the admin panel, with a CSRF token extracted from the body and any
new `Set-Cookie` value captured for reuse. The admin IP didn't need scanning this time — the lab
gives it directly as `192.168.0.1`. Finishing the lab meant repeating the same two-request pattern,
with the second request now a `POST /admin/delete` carrying the CSRF token and `username=carlos`:

```
Request 1: GET / HTTP/1.1  (same as above, refreshes validation)
Request 2: POST /admin/delete HTTP/1.1
Host: 192.168.0.1
Cookie: <session cookies>
Body: csrf=<token>&username=carlos
```

which deleted `carlos` and solved the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the identical bypass using Burp Repeater's connection-grouping
feature: send `/admin` with `Host: 192.168.0.1` alone first to observe it gets redirected, then
duplicate that request into a tab paired with a legitimate `Host` request, group both, and use
Repeater's "Send group in sequence (single connection)" mode with `Connection: keep-alive` set on
the first request. The second request in the group reaches the admin panel exactly as ours did. The
underlying vulnerability and exploitation sequence match precisely.

The difference is, once again, tooling rather than technique — Repeater's grouped-sequence mode is a
GUI feature purpose-built for sending multiple requests down one persistent connection, while our
script achieves the same effect by opening a raw socket and writing both request/response cycles to
it manually. It's the same primitive (two HTTP/1.1 requests, one TCP connection) reached through
different means, and it's the same primitive our raw-socket labs earlier in this series needed for
duplicate Host headers and absolute-URL request lines — this series keeps returning to the same
underlying constraint: standard HTTP client libraries manage connection reuse and header
construction on your behalf specifically to prevent the kind of low-level control these
vulnerabilities require to exploit.

## What This Teaches Us

This lab generalizes a point the earlier routing-SSRF labs only hinted at: a Host header check isn't
actually a per-request guarantee unless it's enforced on every single request, independent of
connection state. "Validate once per connection" is a reasonable-sounding performance optimization
that quietly converts a request-level security control into a connection-level one — and connections
persist longer than the single request an operator might have had in mind when writing the check.
Any validation logic that assumes properties of a request stay constant across a keep-alive
connection needs to either re-validate every request or refuse to make that assumption at all.
