# CSRF where token is duplicated in cookie

**Category:** Cross-Site Request Forgery (CSRF)
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-duplicated-in-cookie

Double-submit cookie validation is a popular CSRF defense precisely because it avoids server-side token storage: the server sets a `csrf` cookie, the client echoes that same value back as a request parameter, and the server just checks the two match. It's a reasonable design as long as an attacker has no way to write cookies into the victim's browser — but that assumption doesn't hold everywhere, and this lab shares the same broken search endpoint as the previous one to prove it.

## The Target

The `change-email` request now validates by comparing the `csrf` request parameter directly against the `csrf` cookie value — no server-side session state involved at all. If they match, the request is trusted.

## The Investigation

`lab_token_duplicated_cookie` runs the same `detect_cookie_injection()` probe against `/?search=` as the previous lab and confirms the same CRLF gadget is present. The key realization here is that double-submit validation doesn't actually require knowing any *real* token value at all — since the check is just "does the cookie equal the parameter," an attacker can invent an arbitrary string, inject it as the cookie via CRLF, and submit the identical string as the form parameter. The server never generated that value and has no way to know it's fabricated; it only ever compares the two copies against each other.

## The Exploit

The wrapper invents `FakeTokenInventedByAttacker123` and passes it to `craft_cookie_injection_payload()` as both the cookie value and the token parameter:

```html
<html><body>
<form action="https://TARGET/my-account/change-email" method="POST">
  <input type="hidden" name="csrf" value="FakeTokenInventedByAttacker123" />
  <input type="hidden" name="email" value="hacker@evil-user.net" />
</form>
<img src="https://TARGET/?search=x%0d%0aSet-Cookie:%20csrf=FakeTokenInventedByAttacker123%3b%20SameSite=None" onerror="document.forms[0].submit()">
</body></html>
```

The victim's browser loads the page, the `<img>` request injects the fabricated `csrf` cookie via the CRLF gadget, the `onerror` handler fires once that request completes, and the form submits with the identical value as the `csrf` parameter. Cookie and parameter match — because the attacker controlled both — so the double-submit check passes and the email changes.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the same technique and the same cookie-injection gadget, with one small cosmetic difference: their invented token value is the short string `fake`, while ours is the longer, more distinctive `FakeTokenInventedByAttacker123`. Neither value carries any special meaning to the server — the double-submit check only cares that cookie and parameter agree — so the choice of string is arbitrary in both cases and doesn't change the exploit's mechanics at all. The CRLF injection URL and the `onerror`-triggered submission pattern are otherwise identical between the two solutions.

Delivery follows the same pattern as the rest of the series: PortSwigger through the exploit server's browser UI, ours through direct API calls.

## What This Teaches Us

Double-submit cookies defend against cross-origin attackers who can send requests but can't read or set cookies on the target's origin — the standard cross-site request forgery scenario. That guarantee collapses completely the moment the target has *any* endpoint that reflects attacker input into a `Set-Cookie` header, because that turns "can't set cookies" into "can set cookies," and the entire defense was built on that single assumption. This lab is a reminder that CSRF defenses don't fail in isolation — an unrelated header-injection bug in a completely different feature (site search) was enough to unravel a defense that looked airtight from the token-validation code alone.
