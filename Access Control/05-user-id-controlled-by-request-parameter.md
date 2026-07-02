# Lab: User ID controlled by request parameter

**Category:** Access Control
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter

Horizontal privilege escalation doesn't need a broken role system — it just needs an identifier
that names *which* record to return, sitting in a place the client controls, with nothing checking
that the identifier belongs to the person asking for it. This is the archetypal IDOR, and it's worth
starting the horizontal-escalation labs here because every later variation in this series is this
same idea wearing a slightly better disguise.

## The Target

After logging in, the account page loads as `/my-account?id=<username>`. For `wiener`, that's
`/my-account?id=wiener`, and the page displays account details including a personal API key.

## The Investigation

The `id` parameter naming the account to display is sitting in plain sight in the URL, set to our
own username. The obvious question — and the one this lab is built to test — is whether the server
actually checks that the session belongs to the account named in `id`, or whether it just looks up
whatever `id` says and returns it regardless of who's asking.

## The Exploit

Logged in as `wiener`, we requested the same endpoint with `carlos`'s username swapped into `id`:

```
GET /my-account?id=carlos
```

```python
_login(client, base, "wiener", "peter")
resp = client.get(f"{base}/my-account", params={"id": "carlos"})
```

The response rendered `carlos`'s account page, API key included, under `wiener`'s own session — no
error, no redirect, no ownership check. We extracted the key with a regex against the response body
and submitted it through the lab's solution endpoint, which flipped the lab to solved.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution is the same request: log in, note that the account page URL contains your
own username in the `id` parameter, send the request to Burp Repeater, change `id` to `carlos`,
retrieve and submit the API key. This matches our approach exactly, both in the parameter tampered
and in what confirms success.

The only difference is delivery — Repeater's manual parameter edit versus our script setting the
`id` query parameter directly on the `httpx` request. The underlying request that hits the server is
functionally identical either way.

## What This Teaches Us

The account page trusted the `id` parameter as the sole source of truth for whose data to return,
with the session cookie only used to confirm *that* someone was logged in, not *which* account they
were entitled to see. That's the core lesson of every IDOR in this series: authentication and
authorization are separate checks, and a system that only performs the first one will happily hand
an authenticated user someone else's data. The fix is to derive the account being displayed from the
session itself, never from a client-supplied parameter.
