# CSRF where token validation depends on token being present

**Category:** Cross-Site Request Forgery (CSRF)
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-validation-depends-on-token-being-present

There's a second, subtler way to implement token validation badly: check the token's *value* correctly whenever it's supplied, but never verify that it was supplied in the first place. A validator built as "if csrf param exists and doesn't match, reject" rather than "if csrf param is missing or doesn't match, reject" leaves exactly one gap — omit the parameter entirely and the whole check evaporates.

## The Target

Same `change-email` endpoint as the previous lab, same `csrf` parameter, same POST-only enforcement this time — but the token check itself is what's incomplete.

## The Investigation

`lab_token_presence` runs the same `detect_csrf()` probes as before. This time the method-switch test came back negative — POST-only is enforced correctly — but the token-omission test succeeded: a request built from `data_no_token`, the version of the payload with the `csrf` key deleted entirely rather than blanked, was accepted. That distinction matters: a blank token (`csrf=`) still triggers the comparison logic and gets rejected, but a request with no `csrf` key present at all skips the comparison because the validator's logic only fires when it finds something to compare against.

## The Exploit

`craft_csrf_payload()` selects its token-omission strategy — a standard auto-submit POST form, built from `data_no_token`, with no `csrf` field anywhere in the markup:

```html
<html><body>
<form action="https://TARGET/my-account/change-email" method="POST">
  <input type="hidden" name="email" value="hacker@evil-user.net" />
  <!-- NO csrf param at all -->
</form>
<script>document.forms[0].submit();</script>
</body></html>
```

Delivered to the victim, the form submits as POST with only the `email` field — exactly the shape that skips validation — and the account's email changes to the attacker-controlled address.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the identical conclusion by the identical method: intercept the request in Repeater, first confirm that *changing* the `csrf` value gets rejected, then delete the parameter outright and observe the request now succeeds. Their template is the same auto-submit POST form with the token field removed — this is an exact match on both the vulnerability and the exploit HTML, not just the underlying concept.

As with the previous labs, the only real divergence is delivery: PortSwigger's solution pastes the HTML into the exploit server through the browser UI and clicks "Store" / "Deliver to victim," while `lab_token_presence` performs the equivalent two HTTP calls to the exploit server's own API directly.

## What This Teaches Us

This is a validation-logic bug wearing the same clothes as the previous lab's routing bug, but it's a distinct mistake worth naming separately: checking a token's *correctness* is not the same as checking its *presence*. Any validator that short-circuits on "parameter not found" rather than treating a missing parameter as an automatic rejection reintroduces the exact vulnerability the token was meant to close. The robust version of this check is always "reject unless a valid token was supplied," never "reject if a token was supplied and it was wrong."
