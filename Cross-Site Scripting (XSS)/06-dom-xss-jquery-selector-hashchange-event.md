# DOM XSS in jQuery selector sink using a hashchange event

**Category:** Cross-Site Scripting (XSS)
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-selector-hash-change-event

Every DOM sink so far has fired on page load, triggered by a query parameter we could put straight
in a URL and send to a victim as a link. This lab introduces a source that never touches
`location.search` at all — the URL fragment (`location.hash`) — combined with a sink that only
processes it in response to a `hashchange` event. That combination means a single crafted link isn't
enough by itself; the payload has to be delivered in a way that actually fires the event after the
page has loaded.

## The Target

The blog's home page listens for `hashchange` events and uses jQuery's `$()` selector function
against the value of `location.hash`, apparently to scroll to or highlight a post matching that
fragment. Because the fragment is never sent to the server as part of the HTTP request, there's no
server-side reflection to look for at all — this is entirely a client-side data flow.

## The Investigation

Two things made this lab different from the earlier DOM sinks: first, `location.hash` changes don't
trigger a page navigation by themselves, so simply loading `https://target/#payload` wouldn't
necessarily fire the vulnerable code path — the `hashchange` event has to actually occur after the
initial page load. Second, jQuery's `$()` function is overloaded: if given a string that looks like
an HTML tag, it creates that HTML rather than treating the string purely as a CSS selector. Passing
attacker-controlled data into `$()` without checking its shape means an attacker can supply markup
instead of a selector, and jQuery will build it.

## The Exploit

To reliably trigger the `hashchange` event rather than relying on the initial page load, we delivered
the payload through an iframe that first loads the page with an empty hash, then appends the
malicious fragment after load — which fires `hashchange` on the embedded page:

```html
<iframe src="https://LAB-ID.web-security-academy.net/#" onload="this.src+='<img src=1 onerror=print()>'"></iframe>
```

We stored this on the exploit server and delivered it to the lab's simulated victim. The iframe loads
the target with an empty hash, then its `onload` handler appends
`<img src=1 onerror=print()>` to the URL, which changes the hash and fires `hashchange`. The
vulnerable code passes that new hash value into `$()`, which builds the `<img>` element and
immediately triggers its broken-image `onerror` handler.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution uses the identical iframe-plus-onload technique to force a `hashchange` after
initial load, and the identical payload appended to the hash. There's no technique divergence at
all — this is one of those labs where the intended solution and ours converge exactly, because the
`hashchange` timing constraint really only has one clean answer. The one deliberate substitution we
made was using `print()` instead of `alert()` as the proof-of-concept function — a known workaround
for headless/cross-origin iframe contexts where `alert()` can be suppressed, which happens to match
what PortSwigger's own solution also uses here. The remaining difference is the usual one: their
walkthrough stores and delivers the exploit through the exploit server's web UI, we did it through
direct POST requests to the same exploit server endpoints.

## What This Teaches Us

This lab shows two related lessons at once. First, DOM sources aren't limited to what shows up in
the HTTP request — `location.hash` never leaves the browser, so a purely server-side security review
(WAF, request logging, server-side input validation) will never see this payload at all. Second,
jQuery's `$()` overloading is a sharp edge: treating "it's just a selector" as safe is wrong when the
function will happily interpret a string starting with `<` as HTML to construct. The fix is to pin
down which behavior is intended — use a dedicated selector API or explicitly validate that the hash
value looks like an element ID before passing it to `$()`, rather than trusting jQuery's automatic
detection to do the safe thing.
