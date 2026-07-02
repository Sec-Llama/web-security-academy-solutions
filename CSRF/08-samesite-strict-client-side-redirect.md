# SameSite Strict bypass via client-side redirect

**Category:** Cross-Site Request Forgery (CSRF)
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-client-side-redirect

SameSite=Strict is the browser's strongest cookie policy — it withholds the cookie from *any* cross-site request, including top-level navigations, closing the gap the previous lab exploited. The catch is that "cross-site" is a property of where a request originates from, not of how many hops it took to get there. If the target site itself has a page that redirects client-side based on attacker-controllable input, an attacker can use that page as a stepping stone: the browser treats the second, redirected request as same-site, because as far as the browser's SameSite logic is concerned, it's not a redirect at all — it's just a new request the page's own JavaScript happened to issue.

## The Target

Session cookies here are set with `SameSite=Strict` explicitly, and the `change-email` endpoint has no token — the site is relying entirely on Strict to block CSRF. Elsewhere, the blog's comment feature sends users to `/post/comment/confirmation?postId=X` after posting, then bounces them back to the post a few seconds later.

## The Investigation

That bounce-back turned out to be handled entirely in the browser: the confirmation page loads a script, `/resources/js/commentConfirmationRedirect.js`, which reads the `postId` query parameter and builds the redirect path from it client-side — `document.location = '/post/' + postId` in effect. Because the `postId` value flows straight into a path with no sanitization, it's a path-traversal gadget: requesting `/post/comment/confirmation?postId=../my-account` doesn't just redirect to `/post/../my-account`, it lands on the account page after the browser normalizes the path, confirming the gadget can redirect to *any* endpoint on the site, not just other blog posts.

The critical property is that this redirect happens via `document.location`, executed by JavaScript already running in the target's own origin — from the browser's perspective, that's a same-site navigation triggered by the site itself, not a cross-site request initiated by the attacker's page. SameSite=Strict never enters the picture, because the request that actually hits `/my-account/change-email` never crossed a site boundary at all; only the *initial* request to the confirmation page did, and that one carries no interesting parameters to protect.

## The Exploit

Converting the real `change-email` POST to an equivalent GET (the endpoint accepts both, since there's no method restriction here — only the SameSite cookie policy was standing in the way) gives a URL that can ride through the redirect gadget:

```html
<script>document.location='https://TARGET/post/comment/confirmation?postId=../my-account/change-email%3femail%3dhacker@evil-user.net%26submit%3d1';</script>
```

The attacker's page sends the victim's browser to the confirmation endpoint — a genuinely cross-site request, so Strict correctly withholds the cookie there, but nothing sensitive happens on that leg. The confirmation page's own script then reads the traversal-laden `postId`, builds `/my-account/change-email?email=...&submit=1` as a path, and issues that as a same-site client-side redirect. This second request *is* same-site, so the session cookie rides along, and the email changes.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution walks the exact same discovery chain — confirm Strict is set on the session cookie, find the confirmation page's client-side redirect script, discover the path-traversal behavior of `postId` by testing `postId=foo` and watching it redirect to `/post/foo`, then confirm `postId=1/../../my-account` lands on the account page to prove arbitrary same-site GET requests are reachable. Their final payload is the same `document.location` assignment pointing at the traversal path into `change-email`, including the same requirement to URL-encode the `&` between `email` and `submit` so it doesn't break out of the outer `postId` parameter early. This is a full match on technique, gadget, and payload structure.

Delivery follows the same pattern as the rest of the series: PortSwigger through the exploit server's browser UI, ours through direct API calls.

## What This Teaches Us

SameSite=Strict protects against cross-*site* requests, not against same-site requests that happen to have been triggered indirectly. A client-side redirect gadget that builds its destination from unsanitized user input effectively lets an attacker smuggle a same-site request through a page the browser already trusts — the attacker's own site is only ever involved in the first, harmless hop. This is really a path-traversal bug in the redirect script wearing a CSRF-shaped consequence: fixing either the traversal (so `postId` can only resolve to known-safe post identifiers) or the redirect mechanism (server-side redirects, which the browser *does* treat as cross-site for SameSite purposes) closes the gap. SameSite alone was never going to be enough on a site that has an open redirect of any kind.
