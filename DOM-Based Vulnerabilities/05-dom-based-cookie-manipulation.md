# DOM-based cookie manipulation

**Category:** DOM-Based Vulnerabilities
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/dom-based/cookie-manipulation/lab-dom-cookie-manipulation

Cookies are usually discussed as a server-side concern — set them with `HttpOnly`, scope them
correctly, don't put secrets in them. This lab is about a different failure mode entirely:
JavaScript that writes attacker-influenced data into a cookie on one page, and a second page that
reads that same cookie back and trusts it enough to render it unsafely. Neither page is doing
anything wrong in isolation; the vulnerability only exists in the handoff between them.

## The Target

Product pages on this site run client-side JavaScript that records the current page as a
`lastViewedProduct` cookie — specifically, `document.cookie = 'lastViewedProduct=' + window.location`,
so the cookie's value is the full URL of whatever product page the user most recently visited. The
home page later reads that cookie back and renders a "Last viewed product" link using it, embedding
the raw cookie value inside an `<a href='...'>` tag.

## The Investigation

The two halves of this bug live on different pages, so tracing it meant following the value across
a page transition rather than a single script. The write side takes `window.location` — which
includes the full current URL, query string and all — and puts it into a cookie verbatim, with no
encoding. The read side takes that cookie value and interpolates it directly into an HTML attribute
without escaping it. If the URL used to set the cookie contains characters that break out of the
`href` attribute's quoting, those characters ride along into the home page's HTML untouched.

Confirming the exact quoting we needed to break required checking the raw HTTP response rather than
assuming from a rendered DOM inspection. A browser's DOM serialization normalizes attribute
quoting to double quotes when you inspect a live page, which would suggest a double-quote breakout
payload — but the server's actual rendered HTML for this `href` used single quotes. Building the
breakout payload against the wrong quote character would have produced markup that looked broken in
a way that didn't actually escape the attribute, so we confirmed the real quote style from the raw
response before committing to a payload.

## The Exploit

`craft_cookie_manipulation_xss()` builds a two-step iframe chain. The iframe first loads a product
page whose URL contains our breakout payload as part of the query string, which poisons the cookie
with that full URL (breakout payload included) the moment the product page's JavaScript runs. Its
`onload` handler then redirects the same iframe to the home page, where the poisoned cookie gets
read back and rendered unsafely:

```html
<iframe src="https://TARGET/product?productId=1&'><img src=x onerror=print()>" onload="if(!window.x)this.src='https://TARGET/';window.x=1;"></iframe>
```

The `'>` at the start of our payload closes the single-quoted `href` attribute early, and
`<img src=x onerror=print()>` becomes live markup rather than attribute text. The `window.x` guard
in the `onload` handler exists to prevent the handler from firing a second time once the iframe has
already navigated to the home page — without it, the `onload` event on the second navigation would
try to redirect the iframe again in a loop. Delivered via the exploit server's store/deliver flow,
the sequence for the victim is: iframe loads the product page, cookie gets poisoned with our full
URL including the breakout markup, `onload` redirects to the home page, the home page reads the
poisoned cookie and writes it into the "Last viewed product" link's `href`, our `img` tag breaks out
of the attribute, its broken `src` throws a load error, and `onerror` calls `print()`.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution uses the same two-step iframe structure — load a poisoned product URL, then
redirect to the home page via the same `if(!window.x)...window.x=1` guard pattern we used — down to
matching that exact loop-prevention idiom:

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/product?productId=1&'><script>print()</script>" onload="if(!window.x)this.src='https://YOUR-LAB-ID.web-security-academy.net';window.x=1;">
```

The one substantive difference is the injected payload itself: their solution breaks out of the
`href` attribute and injects `<script>print()</script>`, while ours injects
`<img src=x onerror=print()>`. Both are valid once the attribute has been broken out of — a
`<script>` tag inserted via `innerHTML`-style rendering into markup that's actually parsed as part
of the page (rather than assigned via `.innerHTML` on an existing element, which suppresses script
execution) will execute normally here, since the home page is rendering the link server-side into
its initial HTML rather than injecting it into an already-parsed DOM. The `onerror` image trick we
used works regardless of which rendering path applies, which is part of why it shows up repeatedly
across this whole lab series as the more universally reliable primitive once you have markup
injection.

## What This Teaches Us

This lab is a clean example of a vulnerability that only exists because of a trust relationship
between two otherwise-reasonable pieces of code: the product page trusted that `window.location`
was safe to store verbatim, and the home page trusted that a cookie value it had "always" set
itself was safe to render without escaping. Neither assumption holds once an attacker controls the
URL that gets fed into the cookie in the first place. It's also a good reminder about verifying
assumptions against ground truth — the actual HTTP response — rather than a browser's normalized
view of the DOM, since the two can differ in exactly the details (quote style) that determine
whether a breakout payload works. The fix is standard output encoding: HTML-escape any cookie value
before writing it into an attribute, and validate cookie values against an expected format (a
relative product path, not an arbitrary string) before trusting them to be a "location," full stop.
