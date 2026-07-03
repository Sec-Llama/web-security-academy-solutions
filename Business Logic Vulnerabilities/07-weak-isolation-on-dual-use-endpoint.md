# Weak isolation on dual-use endpoint

**Category:** Business Logic Vulnerabilities
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-weak-isolation-on-dual-use-endpoint

Some endpoints do double duty without anyone quite intending them to. A "change my password"
endpoint that also happens to accept a `username` parameter isn't necessarily a self-service feature
and an admin feature bolted together on purpose — more often it's one code path that was extended
once to support a second use case, with the assumption that the *other* parameter on the request
would always be present to keep the two cases properly separated. Remove that parameter, and the
separation goes with it.

## The Target

The account management area exposes `POST /my-account/change-password`, which takes
`current-password`, `new-password-1`, `new-password-2`, and a `username` field. Logged in as
`wiener`, the normal flow is submitting your current password alongside the new one twice for
confirmation, and the endpoint updates your own account.

## The Investigation

The presence of a `username` parameter on what's ostensibly a "change my own password" form is
already worth noticing — a self-service endpoint doesn't strictly need to be told whose password it's
changing if it's always the currently authenticated user's. That parameter's existence suggests the
same endpoint is also used somewhere else for changing an arbitrary user's password (an admin
function, most likely), with the current session's identity used as a default when `username` isn't
supplied.

If that's true, the only thing standing between "change my own password" and "change anyone's
password" is whatever check verifies the requester is allowed to act on the `username` they've
specified — and per the lab's guidance on probing mandatory input, the way to find a check like that
is to remove parameters one at a time and see what changes. We tried dropping `current-password`
from the request entirely rather than leaving it blank. If the server's authorization for this
endpoint depends on validating that field, an empty value and a missing value should be handled
differently — and if the server doesn't handle "missing" at all, it may just fall through to
processing the rest of the request without that check running.

## The Exploit

Logged in as `wiener`, we sent the change-password request with `current-password` omitted entirely
and `username` set to the target account:

```
POST /my-account/change-password
username=administrator
new-password-1=hacked
new-password-2=hacked
```

The request succeeded. Logging out and back in as `administrator` with the newly set password
worked immediately — the endpoint had changed the administrator's password on behalf of an
unprivileged, unauthenticated-for-that-account request, simply because the field that should have
authenticated the request wasn't there to check. From the admin panel, deleting `carlos` solved the
lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the same path: log in, access the account page, study the
`POST /my-account/change-password` request in Repeater, remove the `current-password` parameter
entirely, observe that the password changes without it, notice that the `username` parameter
determines whose password is affected, set it to `administrator`, and log in with the new
credentials to reach the admin panel.

This matches our approach exactly — same parameter identified, same removal technique, same
resulting takeover. There's no meaningful divergence in technique here; the only difference is the
usual one in this series, manual parameter editing in Burp Repeater versus a scripted request that
omits the field programmatically.

## What This Teaches Us

The server-side logic almost certainly looked something like "if a `username` is provided and it
differs from the session user, verify `current-password` matches — otherwise change the session
user's own password." That's a reasonable-sounding branch until you consider what happens when
`current-password` is missing rather than merely wrong: the verification step that was supposed to
gate the privileged path never ran at all, because it was written to check the *value* of the
parameter and never confirmed the parameter's *presence* first. Endpoints that serve more than one
privilege level from the same code path need every field that participates in the authorization
decision validated for presence, not just correctness — a request with a required field silently
missing should fail closed, not fall through to a less-restrictive default.
