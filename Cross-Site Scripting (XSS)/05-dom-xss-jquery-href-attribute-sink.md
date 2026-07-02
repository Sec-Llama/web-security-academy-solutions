# DOM XSS in jQuery anchor href attribute sink using location.search source

**Category:** Cross-Site Scripting (XSS)
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-href-attribute-sink

Every DOM XSS lab so far has involved raw HTML injection — breaking out of an attribute or supplying
an event handler that the browser parses as markup. This lab is a different flavor entirely: the
sink is a jQuery call that sets a link's `href` to a URL scheme the browser will happily execute,
`javascript:`. No HTML tags, no angle brackets, no event handlers — just a URL.

## The Target

The application has a "submit feedback" page with a `returnPath` parameter that controls where a
"back" link on that page points. A normal request looks like:

```
GET /feedback?returnPath=/feedback/thanks
```

Client-side JavaScript uses jQuery's `.attr('href', ...)` to set the back link's destination from
that parameter.

## The Investigation

There is nothing to see in the server-side HTTP response here — the server never reflects the
`returnPath` value into the page as visible markup; jQuery sets the `href` attribute purely on the
client, after the page has already loaded. Inspecting the rendered anchor element (not the raw HTML
response) showed our value landing directly as the `href` target, unfiltered. Since `.attr('href', x)`
just assigns whatever string it's given as the link destination, and browsers treat `javascript:...`
as an executable URL scheme when a link with that href is followed, we didn't need to break out of
anything — we just needed the entire attribute value to be a `javascript:` URI.

## The Exploit

We set `returnPath` to a JavaScript URL:

```
GET /feedback?returnPath=javascript:alert(1)
```

The back link's `href` became `javascript:alert(1)`. Clicking that link — via a headless browser
automation that clicked the "back" element rather than just loading the URL — caused the browser to
execute the `javascript:` URI instead of navigating anywhere, firing the alert.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the same path: change `returnPath` to `/` plus a random string,
inspect the element to confirm it lands in the anchor's `href`, then set it to
`javascript:alert(document.cookie)` and click "back" to trigger it. The core technique — recognizing
a jQuery `href` sink and supplying a `javascript:` URI — is identical to ours; we used `alert(1)`
rather than `alert(document.cookie)`, a cosmetic difference in the proof-of-concept function call.
The delivery difference is the now-familiar one: their walkthrough clicks the link by hand in the
browser, we automated the click and listened for the resulting dialog.

## What This Teaches Us

This lab is a useful counterexample to the assumption that DOM XSS always means "inject an HTML
tag." Any sink that hands attacker data to something capable of executing script is dangerous, even
when the sink itself never parses HTML — `.attr('href', ...)` doesn't render markup, but it *does*
let an attacker choose an executable URL scheme. The fix has to match that reality: validate that
user-supplied URLs actually use a safe scheme (`http:`/`https:`/relative paths) before assigning them
to `href`, rather than trusting that "it's not innerHTML, so it's not a sink." Any client-side code
that builds a URL, a redirect target, or a link destination from attacker-controlled data needs the
same scrutiny as one that builds HTML.
