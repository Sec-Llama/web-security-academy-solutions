# Password reset broken logic

**Category:** Authentication
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-broken-logic

A password reset token is only a security control if it's actually checked at the moment it matters — when the new password gets saved, not just when the reset form is first displayed. This lab's reset flow validates the token exactly once, at the wrong step, and then trusts whatever username shows up in the follow-up request.

## The Target

`POST /forgot-password` with a `username` triggers a reset email containing a link with a `temp-forgot-password-token` query parameter. Following that link renders a form to set a new password, which then submits back to `/forgot-password` carrying the token in the URL, plus the username as a hidden form field.

## The Investigation

We ran the reset flow for our own account (`wiener`) first to see the mechanics: request a reset, retrieve the email via the lab's built-in email client, and pull the token out of the reset link with a regex against `temp-forgot-password-token=`. The interesting design detail our notes call out is that the `username` traveling with the final submission is just a hidden form field — nothing ties the token itself to which account it's supposed to apply to on the server side once that POST is received.

## The Exploit

`lab_3_password_reset_broken` demonstrated this by taking our own genuinely valid reset token — issued for `wiener` — and submitting it with the `username` field swapped to `carlos` instead:

```
POST /forgot-password?temp-forgot-password-token=<wiener's real token>
temp-forgot-password-token=<wiener's real token>
username=carlos
new-password-1=pwned123
new-password-2=pwned123
```

That request succeeded, and logging in as `carlos` with `pwned123` authenticated correctly — proving the server never checked that the token it was validating actually belonged to the username it was resetting. As a secondary path, the wrapper also tried submitting with an empty token value entirely for `carlos`, confirming the token isn't required to be present or valid at all for the reset to go through; either gap on its own is enough to break the flow, and our notes record that the token simply "is not checked when submitting new password."

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution demonstrates the same root flaw but through the empty-token path specifically: request a reset, intercept the resulting `POST /forgot-password?temp-forgot-password-token=...` request in Repeater, delete the token's value entirely — in both the URL and the request body — change the `username` field to `carlos`, set a new password, and send. The reset succeeds with no token value present at all.

Both paths prove the identical underlying defect: the server accepts the POST based purely on the `username` field, without ever validating that the accompanying token is valid, non-empty, or actually issued for that account. We happened to demonstrate it primarily via token/username mismatch (a token that's valid, just for the wrong person) with an empty-token fallback, while PortSwigger's walkthrough leads with the empty-token case directly — but either one on its own is sufficient proof the check doesn't exist, and our script's fallback covers the exact case PortSwigger's solution centers on.

## What This Teaches Us

The token here isn't weak — it's simply never re-verified at the step that actually matters. Checking a token when the reset form is *rendered* and then trusting an unrelated `username` field when the new password is *saved* is a classic time-of-check/time-of-use gap dressed up as a two-request flow. The fix is straightforward: the server must look up which account a token belongs to and use *that* account for the password update, ignoring the client-submitted username entirely, and reject the request outright if the token is missing, expired, or doesn't match.
