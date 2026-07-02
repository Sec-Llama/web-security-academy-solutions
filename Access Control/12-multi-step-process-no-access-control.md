# Lab: Multi-step process with no access control on one step

**Category:** Access Control
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step

A privileged action split into multiple steps — request, confirm, execute — often gets its access
control check bolted onto the first step alone, on the assumption that reaching step two implies
you legitimately passed step one. Nothing in HTTP enforces that assumption; each request is
independent, and a step reachable on its own doesn't care how you got there.

## The Target

Promoting a user to administrator, as in the previous lab, runs through `/admin-roles` — but this
version of the workflow is presented as a two-step confirmation flow in the admin panel: an initial
request, followed by a confirmation submission that carries a `confirmed=true` flag.

## The Investigation

We logged in as the administrator first to see the actual multi-step workflow end to end and
confirm what the final confirmation request looks like:

```python
_login(client, base, "administrator", "admin")
resp = client.get(f"{base}/admin")
```

The natural question this workflow raises is whether access control was applied per-request or only
once, at the start of the flow — and if the confirmation step is really just `POST /admin-roles`
with an extra parameter, there's no structural reason a client would need to have gone through step
one at all in order to send step two directly.

## The Exploit

Logged in as `wiener`, we skipped straight to what the confirmation step's request looks like,
submitting all the required parameters — including `confirmed=true` — in a single request, with no
prior "initial" request sent at all:

```
POST /admin-roles
action=upgrade&confirmed=true&username=wiener
-- Key: First step (POST without confirmed) is access-controlled, but confirmation step is NOT
```

```python
resp = client.post(f"{base}/admin-roles", data={
    "action": "upgrade", "confirmed": "true", "username": "wiener"
})
```

The request succeeded, promoting `wiener` to administrator with no earlier step ever attempted. The
lab solved on the next check.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the same outcome — the confirmation request succeeding for a
non-admin user with no valid first step behind it — but arrives there by literally replaying a
captured request rather than reconstructing one: log in as admin, promote `carlos`, and capture the
*confirmation* request specifically in Repeater; then, in an incognito session as the non-admin
user, swap that user's session cookie into the captured request, change the username, and resend it.

We took a more direct route: rather than capturing and replaying an admin-generated request, we
built the confirmation POST from scratch, based on the parameter names already known from Lab 11's
`/admin-roles` endpoint. Both approaches test the identical gap — that the confirmation step accepts
the request independent of session privilege and independent of whether a first step preceded it —
but PortSwigger's method additionally proves that a captured real request from a legitimate flow is
enough to replay under a different session, which is a slightly stronger demonstration on a target
where the exact request shape isn't already known.

## What This Teaches Us

Splitting a sensitive action into multiple steps adds friction for a legitimate user, but friction
isn't authorization. Every step in a multi-step flow is its own independent request and needs its
own independent access control check — a confirmation endpoint that only trusts "you must have come
from step one" without actually verifying step one happened (and happened for *this* user) is
exactly as unprotected as if the entire flow were a single unguarded request.
