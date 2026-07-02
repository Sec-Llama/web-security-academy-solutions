# CSRF with broken Referer validation

**Category:** Cross-Site Request Forgery (CSRF)
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses/lab-referer-validation-broken

The previous lab's fix — requiring the Referer header to always be present — still leaves room for a second, more subtle mistake: how the server compares the Referer's value against its own domain. A check implemented as "does the Referer contain our domain somewhere" rather than "does the Referer's origin exactly equal our domain" can be satisfied by putting the target domain anywhere in the URL, including a query string on an attacker-controlled page.

## The Target

The `change-email` endpoint here requires a Referer header to be present — the previous lab's bypass doesn't work — but the validation logic checks for the target domain as a substring of the header value rather than as the header's actual origin.

## The Investigation

Testing this meant reasoning about what a naive Referer check typically looks like in code: a `contains()` or substring match against the target's hostname, rather than parsing the URL and comparing its scheme and host precisely. If that's the implementation, the check can be satisfied by any Referer value that happens to include the target's domain as text anywhere within it — for instance, as a query string appended to an entirely different, attacker-controlled URL: `https://attacker.com/csrf?TARGET-DOMAIN`. Getting a real browser to send exactly that Referer value from the attacker's own page requires manipulating the page's URL after load, since the Referer a browser sends is normally derived from the page's actual address, not an arbitrary string.

`history.pushState()` provides that manipulation — it lets a script rewrite the visible URL (and by extension, what the browser considers the current page's address for Referer purposes) without triggering a real navigation. Pairing that with a `Referrer-Policy: unsafe-url` response header matters too: browsers strip query strings from the Referer under more conservative default and origin-only Referrer Policies, so without explicitly forcing the full URL to be sent, the injected domain in the query string would simply be cut off before it ever reached the server.

## The Exploit

`craft_csrf_payload()`'s contains-bypass strategy rewrites the page's URL to embed the target's domain as a query string immediately before submitting the form, and pairs the payload with a custom response header on the exploit server:

```html
<html>
<body>
<form action="https://TARGET/my-account/change-email" method="POST">
  <input type="hidden" name="email" value="hacker@evil-user.net" />
</form>
<script>
  history.pushState("", "", "/?TARGET_DOMAIN");
  document.forms[0].submit();
</script>
</body></html>
```

```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Referrer-Policy: unsafe-url
```

When the victim's browser loads the page, `history.pushState()` rewrites the address bar to include the target's domain as a query string without navigating anywhere, and the `Referrer-Policy: unsafe-url` header ensures the full resulting URL — query string included — is sent as the Referer on the subsequent form submission. The Referer that reaches the server looks like `https://EXPLOIT-SERVER/?TARGET-DOMAIN`: a substring match against the target's domain succeeds, even though the request's actual origin is the attacker's exploit server.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches this via the same reasoning and the same payload structure: confirm the domain-substitution rejection first, then construct a Referer that embeds the correct domain as a query string on an unrelated host — their example uses `Referer: https://arbitrary-incorrect-domain.net?YOUR-LAB-ID.web-security-academy.net` — and confirm the server accepts it. Their exploit uses the identical `history.pushState("", "", "/?YOUR-LAB-ID.web-security-academy.net")` call, and they call out the same requirement we implemented: adding `Referrer-Policy: unsafe-url` to the exploit server's response headers so the browser doesn't truncate the query string before sending the Referer. This is a full match on technique, payload structure, and the supporting response header.

Delivery follows the pattern used throughout the series: PortSwigger's walkthrough is manual through the exploit server's UI; our script performs the equivalent deliver call, with the custom response headers passed alongside the HTML body in the same API request.

## What This Teaches Us

A substring check is a systemic failure mode that shows up again and again across different defenses — it appeared as a naive domain match here, and it's the same underlying mistake as any allowlist implemented with `contains()` instead of exact comparison. The fix for Referer validation specifically is to parse the header as a URL and compare its scheme and host precisely against an allowlist of expected values, never to search for the expected domain as a substring anywhere in the header. More broadly, this lab is a reminder that Referer-based CSRF defense sits on genuinely shaky ground even when implemented carefully: the header's presence, format, and truncation behavior are all governed by `Referrer-Policy`, which the *sender's* page controls, not the receiving server — putting a meaningful piece of the defense's integrity outside the defending application's own control.
