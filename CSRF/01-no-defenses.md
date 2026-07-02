# CSRF vulnerability with no defenses

**Category:** Cross-Site Request Forgery (CSRF)
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/csrf/lab-no-defenses

CSRF works because browsers are helpful in exactly the wrong way: they attach a user's session cookie to every request that goes to a site, regardless of which page triggered that request. If a state-changing endpoint has no unpredictable parameter tying the request to a specific, deliberate user action, an attacker doesn't need to steal anything — they just need the victim's browser to visit a page that fires the request for them. This lab is that scenario in its purest form, and it's the baseline every later CSRF lab in this series builds on.

## The Target

The application is a simple account management panel. Changing your email address sends:

```
POST /my-account/change-email
email=you@example.com
```

There's no CSRF token in that request, no Referer check, no SameSite restriction beyond the default — the request's only authority is the session cookie automatically attached by the browser.

## The Investigation

There wasn't much to probe here — the lab's premise already tells us the defenses are absent, and confirming that took one look at the `change-email` request: a single `email` parameter, no companion token field anywhere in the account page's HTML, no other check visible in the response. Our `CSRF.py` lab wrapper (`lab_no_defenses`) reflects that directly: rather than running the full detector, it builds a `CSRFContext` with `no_token_works=True` set immediately, since that's the exact condition this lab is testing for.

The interesting part of a lab this simple is the delivery mechanism, since that's what's automated. The wrapper logs into the lab with the standard `wiener:peter` credentials, pulls the exploit server's URL straight out of the lab's landing page via regex, then hands the crafted HTML to two helper functions that POST directly to the exploit server's own API: one call with `formAction: STORE` to save the page, and a second with `formAction: DELIVER_TO_VICTIM` to trigger the simulated victim's browser to load it. That's the same two actions a human performs by clicking "Store" and "Deliver to victim" in the exploit server's web UI — just issued as raw HTTP requests instead of button clicks.

## The Exploit

`craft_csrf_payload()` falls through to its basic case — an auto-submitting form with no token field at all:

```html
<html><body>
<form action="https://TARGET/my-account/change-email" method="POST">
  <input type="hidden" name="email" value="hacker@evil-user.net" />
</form>
<script>document.forms[0].submit();</script>
</body></html>
```

Delivered to the victim, the browser loads the page, the script fires the form's `submit()` immediately, and the POST goes out carrying the victim's own session cookie. The server has no way to distinguish this from the victim genuinely clicking "Update email" — the request is identical in every way that matters to the backend. Checking the lab's solved state after a five-second wait confirmed the victim's email had changed.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's published solution reaches the same HTML, field for field: intercept the real `change-email` request in Burp, then either use Burp Suite Professional's "Generate CSRF PoC" (with the auto-submit option enabled) or hand-write the Community Edition template — which is the exact form-plus-script structure above.

The only real difference is delivery, and it's the same difference that shows up throughout this series: PortSwigger's walkthrough pastes the HTML into the exploit server's "Body" field through the browser and clicks "Store" then "Deliver to victim" by hand. Our script does the identical two actions by POSTing to the exploit server's endpoint directly with `httpx`. For a single-page payload like this one, the two approaches produce byte-identical requests — the difference is purely who's clicking versus who's scripting.

## What This Teaches Us

The email-change endpoint doesn't fail because of a coding mistake in the traditional sense — there's no injection, no broken auth. It fails because "the request came with a valid session cookie" was treated as sufficient proof of the user's intent, when a cookie only proves *which* session is acting, not that the *user* chose to act. The fix is a CSRF token: a value the server generates, ties to the session, and requires on every state-changing request — something an attacker's page can't predict or read cross-origin. Every later lab in this series is really about probing how that fix gets implemented badly.
