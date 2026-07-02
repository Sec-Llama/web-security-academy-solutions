# Lab: Referer-based access control

**Category:** Access Control
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/access-control/lab-referer-based-access-control

The `Referer` header exists to tell a server which page a request came from, and browsers set it
automatically — which makes it tempting to use as an access control signal, since a legitimate
navigation from an admin page will naturally carry that page's URL in the header. The problem is
that "automatically set by the browser" and "trustworthy" are unrelated properties. Any HTTP client
that isn't a browser following a real link can put whatever string it wants in that header.

## The Target

The `/admin-roles` promotion endpoint from the two previous labs shows up here gated by a check on
the `Referer` header rather than the request method or the confirmation flow: reaching it without a
`Referer` pointing back at `/admin` returns an unauthorized response, even with the right method and
parameters.

## The Investigation

We logged in as administrator first to see the endpoint's normal invocation and confirm the
parameter shape, consistent with the previous two labs in this sequence:

```python
_login(client, base, "administrator", "admin")
resp = client.get(f"{base}/admin")
```

With the endpoint and parameters already known, the specific question this lab poses is whether the
`Referer` check is actually verifying anything about the request's provenance, or just checking that
some particular string is present in a header the client fully controls.

## The Exploit

Logged in as `wiener`, we sent the promotion request directly, setting the `Referer` header by hand
to the value the check expected instead of navigating from the admin page for real:

```
GET /admin-roles?username=wiener&action=upgrade
  with Referer: {base}/admin    -- Server checks Referer instead of session role
```

```python
resp = client.get(
    f"{base}/admin-roles",
    params={"username": "wiener", "action": "upgrade"},
    headers={"Referer": f"{base}/admin"}
)
```

Without any `Referer` header, this request returns "Unauthorized"; with the forged header attached,
it succeeded, promoting `wiener` to administrator. The lab solved on the next check.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the bypass by replaying a captured legitimate request rather than
constructing a forged header from scratch: log in as admin, promote `carlos`, and capture that
promotion request in Repeater — a request that already carries a genuine `Referer: /admin` header,
because it came from a real browser navigation off the admin panel. Then, in an incognito session as
the non-admin user, they swap in that user's session cookie, change the username to their own, and
replay the captured request as-is. Because the captured request's `Referer` header travels along
with it unchanged, the check passes without PortSwigger ever needing to add or edit that header
directly — it was already the correct value from the original admin action.

We solved this differently: rather than capturing and replaying a request that happened to already
carry the right `Referer`, we set the header explicitly on a freshly constructed request. Both
approaches defeat the exact same check for the same reason — the server treats the `Referer` value
as proof of legitimate navigation from `/admin`, and neither a replayed header nor a hand-set one is
distinguishable from a real one, because nothing about the header format proves where a request
actually originated. Setting it directly is arguably the more direct demonstration that the value
itself is the entire control, with no dependency on capturing a specific prior request first.

## What This Teaches Us

`Referer` is client-supplied metadata, not a credential — indistinguishable, from the server's
point of view, whether it arrived because a browser navigated from `/admin` or because an HTTP
client set the header string directly. Using it as an authorization signal conflates "this request
looks like it came from an authorized workflow" with "this request came from an authorized user,"
and only the second one is a security property. The fix is the same theme running through this
entire lab series: authorization decisions belong to server-side session state, not to any value the
client sends along for the ride.
