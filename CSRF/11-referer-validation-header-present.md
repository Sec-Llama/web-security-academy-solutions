# CSRF where Referer validation depends on header being present

**Category:** Cross-Site Request Forgery (CSRF)
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses/lab-referer-validation-depends-on-header-being-present

Some applications skip CSRF tokens entirely and instead check the `Referer` header, on the assumption that a cross-site request will always carry the attacker's domain in that header and can be rejected on sight. That assumption has a gap symmetrical to the "token validation depends on token being present" lab earlier in this series: checking the Referer's *value* correctly is not the same as requiring the Referer to be present at all, and there are legitimate ways for a browser to send no Referer whatsoever.

## The Target

The `change-email` endpoint carries no CSRF token here; instead, the server inspects the incoming `Referer` header and rejects the request if it doesn't match the site's own domain.

## The Investigation

Confirming the defense meant tampering with the Referer value first — changing the domain got the request rejected, proving the header genuinely is being checked. The next question was what happens if the header isn't sent at all, rather than sent with a wrong value. Browsers already have a standard mechanism for suppressing the Referer header on outgoing requests: the `Referrer-Policy` directive, settable per-page via a `<meta>` tag. If the server's validation logic only fires when it finds a Referer header to compare, omitting the header entirely — rather than sending a bad one — takes the same path as the previous "token present" bug: no value to check means no check happens.

## The Exploit

`craft_csrf_payload()`'s Referer-suppression strategy adds a `<meta name="referrer" content="never">` tag ahead of the usual auto-submit form:

```html
<html>
<head><meta name="referrer" content="never"></head>
<body>
<form action="https://TARGET/my-account/change-email" method="POST">
  <input type="hidden" name="email" value="hacker@evil-user.net" />
</form>
<script>document.forms[0].submit();</script>
</body></html>
```

With that policy in place, the browser omits the `Referer` header entirely on the form submission. The server's validation, which only rejects requests when the header is present and wrong, finds nothing to check and lets the request through, changing the victim's email.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the same discovery path — confirm a wrong Referer domain is rejected, confirm deleting the header entirely is accepted — and lands on the same meta-tag suppression technique, with one detail worth calling out honestly: their published solution uses `<meta name="referrer" content="no-referrer">`, while our verified payload (recorded in `CSRF.txt` and confirmed working against the lab) uses `content="never"`. Both are documented values for the `Referrer-Policy` mechanism — `no-referrer` is the current standard keyword, and `never` is an older, still browser-supported alias for the same behavior — but they are genuinely different literal strings, and we're noting the discrepancy rather than smoothing over it. Functionally, both suppress the Referer header the same way and both solved this lab.

Delivery follows the pattern seen throughout the series: PortSwigger's walkthrough builds and stores the exploit manually through the browser; our script performs the equivalent through direct exploit-server API calls.

## What This Teaches Us

Referer-based CSRF defense inherits the exact same structural weakness as incomplete token validation: checking a value correctly when it's present is not equivalent to requiring that value to exist. A page under the attacker's control can choose not to send a Referer header at all through a standards-compliant, one-line `Referrer-Policy` directive — no exotic browser bug required. Any Referer check built to defend against CSRF needs to treat a missing header as an automatic rejection, exactly like a missing CSRF token, rather than as a case that simply skips validation.
