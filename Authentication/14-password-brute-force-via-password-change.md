# Password brute-force via password change

**Category:** Authentication
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-brute-force-via-password-change

Brute-force protection tends to live where the obvious attack surface is: the login form. This lab's login form is presumably well protected. Its password-change form, reachable only once already authenticated, checks the submitted current password against the real one and happily tells you — through a slightly different error message — whether you got it right, with no lockout of its own at all.

## The Target

`POST /my-account/change-password` takes `current-password`, `new-password-1`, and `new-password-2`, plus a `username` field that our notes describe as a hidden input on the form — meaning it's client-submitted and, per the lab's design, changeable to a username other than the one that's actually logged in.

## The Investigation

Testing the form's own error handling revealed the oracle. Per our verified notes: submitting an incorrect `current-password` alongside two *different* new-password values produces `"Current password is incorrect"`. Submitting the *correct* `current-password` with two mismatched new-password values instead produces `"New passwords do not match"` — a completely different message, only reachable if the current password check actually passed. That distinction is the entire vulnerability: the response tells you whether your `current-password` guess was right before the request has done anything else.

One thing our notes flag explicitly as a trap: if the two new-password values *match* while `current-password` is wrong, the account gets locked instead of returning a clean error. The mismatch between `new-password-1` and `new-password-2` isn't incidental to the exploit — it's what prevents the request from ever reaching the branch that would lock the account, since a matching pair with a wrong current password apparently gets treated as a real (failed) change attempt rather than a discardable validation error.

## The Exploit

`exploit_password_change_brute` (via `lab_12_password_change_brute`) logs in as our own valid account (`wiener:peter`) once, then loops through the 100-entry candidate password list. Each iteration re-fetches `/my-account` for a fresh CSRF token — required per request — and submits:

```
POST /my-account/change-password
username=carlos
current-password=<candidate>
new-password-1=new1
new-password-2=new2
```

with `new-password-1` and `new-password-2` deliberately different, exactly as the investigation established. The loop checks each response for `"new passwords do not match"`; the first candidate that produces that specific message is `carlos`'s real current password, confirmed without a single attempt against `/login` or its brute-force protection. Because the endpoint showed no lockout behavior of its own across a full 100-password sweep, this ran sequentially with no need for concurrency — a hundred requests sequentially was fast enough on its own. Logging in as `carlos` with the recovered password and loading `/my-account` completed the solve.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution documents the identical oracle and exploitation shape: log in, observe the two distinct error messages depending on whether the current password was right, then send `POST /my-account/change-password` to Burp Intruder with `username` changed to `carlos`, a payload position on `current-password`, and `new-password-1`/`new-password-2` deliberately mismatched to avoid the account-lock path. A grep-match rule targeting `"New passwords do not match"` flags the correct candidate.

This is a case of matching technique down to the specific request shape — including the same deliberate mismatch to sidestep the lockout trap. The only difference is execution: Burp Intruder's Sniper attack with a grep-match filter versus our sequential Python loop pulling a fresh CSRF token before each request and string-matching the response directly.

## What This Teaches Us

Brute-force protection scoped only to `/login` leaves every other endpoint that re-validates a password exposed to the exact same style of attack — and password-change forms are a natural target, since they exist specifically to check a credential against the stored value. Any endpoint that verifies a password needs the same rate limiting as the primary login form, and its error responses need to avoid distinguishing *why* a request failed in ways that leak which part of the input was correct.
