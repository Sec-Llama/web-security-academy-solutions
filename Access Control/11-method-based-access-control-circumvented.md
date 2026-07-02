# Lab: Method-based access control can be circumvented

**Category:** Access Control
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/access-control/lab-method-based-access-control-can-be-circumvented

Access control checks written against a specific HTTP method are checking the wrong thing. `POST`
versus `GET` is routing metadata, not identity — and a framework that maps both verbs to the same
underlying handler by convenience, while an authorization filter only bothers to inspect one of
them, has built a bypass into its own routing layer.

## The Target

Promoting a user to administrator goes through `/admin-roles`, invoked with a `POST` request
carrying `username` and `action=upgrade`. Requesting that same action as a low-privileged user over
`POST` correctly returns an authorization failure.

## The Investigation

We first logged in as the administrator to observe the legitimate promotion flow and confirm the
actual endpoint and parameter names, since guessing at both would have wasted requests:

```python
_login(client, base, "administrator", "admin")
resp = client.get(f"{base}/admin")
action_match = re.search(r'action="([^"]*)"', resp.text)
```

That gave us `/admin-roles` and the `username`/`action` parameter pair straight from the admin
panel's own promotion form, rather than assuming them.

With the endpoint confirmed, the question was whether the authorization check protecting it was
tied to the request's method rather than the user's actual privileges. Frameworks frequently route
`GET` and `POST` to the same handler for convenience, and it's common for an authorization
middleware or decorator to be attached to one specific method during development and never revisited
when a route also accepts others.

## The Exploit

Logged in as `wiener` (a non-admin account), we sent the same promotion action as a `GET` request
instead of `POST`:

```
GET /admin-roles?username=wiener&action=upgrade
```

```python
_login(client, base, "wiener", "peter")
resp = client.get(f"{base}{upgrade_path}", params={
    "username": "wiener", "action": "upgrade"
})
```

The request succeeded — `wiener` was promoted to administrator using an account that had just been
explicitly denied the same action over `POST`. The lab solved on the next check.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the same `GET`-based bypass, but by way of an intermediate diagnostic
step our script skipped. Their walkthrough: capture the admin's promotion request in Repeater, swap
in the non-admin session cookie and confirm it returns "Unauthorized" over `POST`, then change the
method string from `POST` to the deliberately invalid `POSTX` and observe the response change to
"missing parameter" instead of "Unauthorized." That shift in error message is the actual signal —
it shows the authorization check only fires for the literal string `POST`, while *any other* method
value reaches the parameter-validation logic behind it unauthenticated. Only after confirming that
do they convert the request to a real `GET` and replay it.

We went straight to `GET` without that `POSTX` intermediate step, because we already understood
method-based access control as a class of bug well enough to test the most likely bypass method
directly rather than needing the diagnostic to reveal that a bypass existed at all. The `POSTX` step
is genuinely more rigorous, though — on an unfamiliar target, it's the difference between "confirmed
the check is method-string-based before touching a real verb" and "got lucky that `GET` was the verb
the router still accepted."

## What This Teaches Us

The authorization check here was correctly written for `POST` and simply never applied to the other
verbs the router happened to accept for the same handler. That's a narrower version of the same
mistake as Lab 10: one layer (routing) treats `GET` and `POST` as interchangeable paths to the same
logic, while another layer (authorization) only inspects one of them. The fix is to enforce
authorization at the handler level, independent of which HTTP method reached it — or, just as
effectively, to stop routing sensitive actions through multiple methods in the first place.
