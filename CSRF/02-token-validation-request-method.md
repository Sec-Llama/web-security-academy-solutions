# CSRF where token validation depends on request method

**Category:** Cross-Site Request Forgery (CSRF)
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-validation-depends-on-request-method

A CSRF token defense is only as strong as the code path that enforces it. It's a common shortcut for a developer to wire token validation into the POST handler and assume that's the only way the action can be triggered — forgetting that plenty of frameworks will happily route the same logic from a GET request too. This lab is that shortcut turned into an exploitable gap.

## The Target

The account panel's email change now carries a token:

```
POST /my-account/change-email
csrf=<token>&email=you@example.com
```

Tampering with `csrf` gets the request rejected, so the token is clearly being checked — the question is whether it's checked *everywhere* the action can be reached.

## The Investigation

Our `lab_token_method` wrapper logs in, pulls a legitimate CSRF token from `/my-account`, and then hands both to `detect_csrf()` — the Layer 1 detector shared across most of these labs. It runs four automated probes against the endpoint: drop the token entirely, send it blank, convert the same request to GET, and strip the Referer header. Against this target, the interesting result came back on the method switch: sending the parameters as a GET query string instead of a POST body succeeded without the token being checked at all. The token-validation code apparently only runs inside the POST branch of the request handler; reach the same logic via GET and that branch — and its check — never executes.

## The Exploit

With `ctx.method_switch_works` set, `craft_csrf_payload()` picks its first strategy: a GET request delivered via an `<img>` tag, since an image load is a same-origin-agnostic way to fire an arbitrary GET without needing a script or form submission:

```html
<img src="https://TARGET/my-account/change-email?email=hacker@evil-user.net">
```

The browser fetches the "image," the request lands on `/my-account/change-email` as a GET carrying the victim's session cookie, and because the token check never runs on that path, the email changes. The response won't actually render as an image — the `<img>` tag doesn't care, since it only exists to force the browser to issue the request.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution walks the identical discovery path: capture the request in Proxy history, send it to Repeater, confirm tampering with `csrf` gets rejected, then use Burp's "Change request method" to convert it to GET and observe that the converted request succeeds with no token validation at all. Their exploit template omits an explicit `method` attribute on the form (which defaults to GET) rather than using an `<img>` tag, but the two are functionally the same trick — both cause the browser to issue a bare GET to the vulnerable endpoint. This is a case where the underlying flaw and the discovery process match exactly; only the specific HTML tag used to fire the GET request differs.

The delivery mechanism follows the same pattern as the rest of this series: PortSwigger's walkthrough uses "Generate CSRF PoC" or a hand-pasted template through the exploit server's browser UI, while our script builds the same payload and posts it straight to the exploit server's API.

## What This Teaches Us

"The token is validated" isn't a complete statement of a defense — it has to be "the token is validated on every code path that performs this action," and that's a much easier property to break by accident. A method-based routing shortcut (validate on POST, ignore on GET) is exactly the kind of gap that's invisible from the happy path and only shows up when someone deliberately tries the alternate route. The fix isn't really about CSRF tokens at all — it's about making sure a state-changing action has exactly one entry point, with the token check enforced regardless of which HTTP method reaches it.
