# Lab: User role controlled by request parameter

**Category:** Access Control
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter

Some applications decide who you are once, at login, and then trust whatever the client hands back
on every request after that. When that trust is placed in a cookie the client can freely edit, the
entire access control model collapses into a single value an attacker just has to set correctly.

## The Target

The site issues an `Admin` cookie on login. A normal user's session carries `Admin=false`, and the
`/admin` panel checks that cookie before granting access to the same kind of user-deletion
functionality seen in the previous labs.

## The Investigation

Once we knew the gate was a cookie value rather than a real session-backed role, the plan was
straightforward: log in normally as `wiener`, then overwrite that one cookie before hitting
`/admin`. The overwrite is where we hit a real snag.

Our first attempt set the cookie on the client without specifying a domain, and it silently didn't
take — the server-set `Admin=false` cookie stayed in place instead of being replaced. `httpx`'s
cookie jar treats a cookie's domain as part of its identity, so setting a same-named cookie without
matching the domain the server used creates a *second* cookie rather than overriding the first one,
and whichever one the server reads first wins. We fixed it by binding the override to the lab's
actual hostname:

```
Cookie: Admin=true
-- NOTE: httpx cookie.set() needs domain= to override server-set cookies
```

```python
domain = urlparse(base).hostname
client.cookies.set("Admin", "true", domain=domain)
```

With the domain specified, the override actually replaced the server's cookie instead of shadowing
it.

## The Exploit

```python
_login(client, base, "wiener", "peter")
client.cookies.set("Admin", "true", domain=domain)
resp = client.get(f"{base}/admin")
```

`/admin` returned the full admin panel. We located the delete link for `carlos` in the response and
followed it, which deleted the account and solved the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the same end state — an `Admin=true` cookie accompanying the request
to `/admin` — through a different mechanism. Their approach intercepts the *login response* in Burp
Proxy with response interception enabled, edits the `Set-Cookie: Admin=false` header down to
`Admin=true` before it ever reaches the browser, and lets the browser store the already-correct
value.

We didn't intercept the server's response at all; we let it set `Admin=false` normally and then
overwrote it client-side on the next request. Both approaches are valid because the access control
check only cares about the `Admin` cookie value present on the request that hits `/admin` — it
doesn't matter whether that value arrived because the server was tricked into issuing it, or
because the client rewrote it afterward. The domain-scoping issue we ran into is really a
`httpx`-specific implementation detail of the second approach; Burp's interception method sidesteps
it entirely by never letting the "wrong" cookie exist in the first place.

## What This Teaches Us

A boolean flag sitting in a client-writable cookie is not an access control decision — it's a
suggestion. The server accepted `Admin=true` at face value on every subsequent request instead of
deriving the user's role from something it actually controlled, like a server-side session lookup.
Whether an attacker edits the value in Burp before the browser ever sees it, or overwrites it in
their own HTTP client afterward, the outcome is identical, because the flaw is the same either way:
the server is asking the client what permissions the client should have.
