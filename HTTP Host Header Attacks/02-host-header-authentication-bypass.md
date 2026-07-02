# Host header authentication bypass

**Category:** HTTP Host Header Attacks
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/host-header/exploiting/lab-host-header-authentication-bypass

Plenty of applications treat "the request came from inside the network" as a substitute for actual
authentication, on the assumption that internal-only functionality is unreachable from outside.
That assumption depends entirely on the network actually enforcing it. When the check for
"internal" is nothing more than a Host header comparison, the assumption collapses — anyone who can
send an HTTP request can also send one that claims to be internal.

## The Target

`GET /admin` on this application returns a 401 for a normal request. Somewhere behind that response
is logic deciding whether the caller counts as trusted, and the only thing distinguishing a "trusted"
request from any other is a header value the client controls.

## The Investigation

We requested `/admin` directly and got the 401. The natural next move for a Host-header-driven
access check is to try values a backend might treat as synonymous with "this request originated on
the server itself" — `localhost` and `127.0.0.1` are the obvious first guesses, since those are the
canonical ways a service refers to itself.

`GET /admin` with `Host: localhost` returned 200 with the full admin panel. That confirmed the
access control logic was keyed entirely off the Host header rather than anything about the actual
network path the request took.

One thing our testing surfaced that isn't obvious from the 401 alone: the bypass only works if a
session cookie is already present. Hitting `/admin` with `Host: localhost` and no cookie at all
returned 403, not 200 — a different rejection than the plain 401 we got with a legitimate Host and
no override. Visiting the homepage first to pick up a session cookie, then reusing that cookie on
the `Host: localhost` request, was what actually got us to 200. Without that step this lab looks
harder than it is, because the naive version of the bypass (no cookie, just the header swap)
produces a response that reads as "still blocked" rather than "missing a prerequisite."

## The Exploit

With a session cookie in hand:

```
GET /admin
Host: localhost
Cookie: session=<value from homepage visit>
```

This returned the admin panel, including the option to delete users. From there:

```
GET /admin/delete?username=carlos
Host: localhost
Cookie: session=<value>
```

deleted `carlos` and solved the lab. Our capability script wraps this as `exploit_auth_bypass()`
followed by the delete request, both carrying the same client (and therefore the same cookie jar)
throughout.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution takes a slightly more exploratory path to the same endpoint: send the
initial `GET /` to Repeater, notice an arbitrary Host header still loads the home page, then check
`/robots.txt` — which discloses the `/admin` path directly. Requesting `/admin` normally returns an
error message that itself reveals the panel is meant to be reachable by "local users," which is the
hint toward trying `Host: localhost`. From there the official path matches ours exactly: swap the
Host header to `localhost`, get the admin panel, then change the request line to
`GET /admin/delete?username=carlos` to finish the lab.

The one gap between the two write-ups is that PortSwigger's steps don't call out the session-cookie
requirement explicitly — likely because working through Burp's browser naturally picks up a session
cookie along the way, so the constraint never becomes visible as a separate obstacle. Scripting the
same sequence in isolation made it visible immediately, since a bare `httpx` request has no cookie
jar until you explicitly populate one.

## What This Teaches Us

The vulnerability here isn't a broken authentication scheme so much as an access control that was
never actually authentication at all — it's a heuristic ("this looks like a local request") standing
in for a real trust boundary. Because the heuristic is entirely client-controlled, it provides
exactly zero security against anyone who knows to try it. This lab is also a useful reminder that
"access denied" responses can differ in ways that matter: the plain 401 and the cookie-less 403 on
`Host: localhost` are both failures, but they're failing for different reasons, and only one of them
is the one step away from success. The durable fix is the same one that applies to every lab in this
series — never let a client-supplied header stand in for verified identity or network position.
