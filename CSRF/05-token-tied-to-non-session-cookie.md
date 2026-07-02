# CSRF where token is tied to non-session cookie

**Category:** Cross-Site Request Forgery (CSRF)
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-tied-to-non-session-cookie

Binding a CSRF token to *a* cookie sounds like the right fix after the previous lab, but which cookie it's bound to matters enormously. If the token is checked against a secondary cookie — call it `csrfKey` — rather than the session cookie itself, an attacker who can get their own `csrfKey` value written into the victim's browser has effectively re-created the same session-binding gap from a different angle, because the two cookies are no longer forced to agree on whose session is whose.

## The Target

The email-change request now carries both a `csrf` token and a separate `csrfKey` cookie, and the two are checked against each other rather than against the session. Elsewhere on the site, the search function reflects its query term straight into the response — a detail that turns out to matter.

## The Investigation

`lab_token_non_session_cookie` logs in, records the session's own `csrf` token and `csrfKey` cookie value, then calls `detect_cookie_injection()` — a Layer 1 detector built specifically for this family of labs. It probes the `/?search=` endpoint with a CRLF sequence (`%0d%0a`) injected into the query, attempting to smuggle a `Set-Cookie` header into the response:

```
/?search=x%0d%0aSet-Cookie:%20csrfTestCookie=testValue123%3b%20SameSite=None
```

The response came back with the injected cookie present in a `Set-Cookie` header, confirming the search endpoint has no output encoding on that parameter and will happily let us set arbitrary cookies in whoever's browser makes the request — including a victim's, if we can get their browser to load that URL.

## The Exploit

`craft_cookie_injection_payload()` combines both pieces: a form carrying the attacker's `email` target and the attacker's own valid `csrf` token, plus an `<img>` tag pointed at the CRLF-injection URL that plants the attacker's `csrfKey` cookie value into the victim's browser. The `onerror` handler — which fires because the search response is HTML, not an image, so the image "fails" to load — triggers the form submission only after the cookie injection request has completed:

```html
<html><body>
<form action="https://TARGET/my-account/change-email" method="POST">
  <input type="hidden" name="csrf" value="ATTACKER_CSRF_TOKEN" />
  <input type="hidden" name="email" value="hacker@evil-user.net" />
</form>
<img src="https://TARGET/?search=x%0d%0aSet-Cookie:%20csrfKey=ATTACKER_CSRFKEY%3b%20SameSite=None" onerror="document.forms[0].submit()">
</body></html>
```

When the victim loads this page, their browser first receives the injected `csrfKey` cookie — overwriting whatever value they had — then submits the form carrying the attacker's matching `csrf` token. Since `csrfKey` and `csrf` now agree with each other (both belong to the attacker), the check passes even though the request is running under the victim's session cookie.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the same exploit through a more thorough manual verification process: first confirm that tampering with the `session` cookie logs the tester out (proving it's the real auth cookie) while tampering with `csrfKey` merely triggers a token rejection (proving it's a separate, non-session cookie); then explicitly swap `csrfKey` and `csrf` between two logged-in test accounts in Repeater to confirm cross-account acceptance, before building the same CRLF cookie-injection exploit we did. That two-account swap test is a manual confirmation step our script skips, going directly from the lab's stated premise to construction — the resulting exploit HTML, though, lines up field for field, including the same `onerror`-triggered submission sequence.

Delivery again follows the pattern seen throughout this series: theirs through the exploit server's browser UI, ours through direct API calls from the script.

## What This Teaches Us

The lesson compounds the previous lab's: it's not enough to tie a CSRF token to *some* cookie — it has to be tied to the actual authenticated session cookie, and that cookie has to be one the application protects from being overwritten by an unrelated, unauthenticated endpoint. Here, two separate application weaknesses combined into one exploit: a CSRF token architecture that trusts a non-session cookie as its source of truth, and a completely unrelated reflected-input bug in the search feature that let an attacker plant arbitrary cookies via CRLF injection. Neither flaw alone would have been enough — chaining them together made the token binding meaningless.
