# DOM XSS in innerHTML sink using source location.search

**Category:** Cross-Site Scripting (XSS)
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-innerhtml-sink

This lab looks almost identical to the previous one on the surface — the same `location.search`
source, the same search box, the same absence of any server-side reflection to inspect — but the
sink is different in a way that matters: `innerHTML` instead of `document.write()`. That single
difference changes what payload actually works, which is the point of studying DOM sinks
individually rather than treating "DOM XSS" as one interchangeable technique.

## The Target

Same blog application, same search functionality, same client-side pattern of reading
`location.search` and writing it into the page without going through the server. The difference only
becomes visible once you look at *how* the value gets written.

## The Investigation

`innerHTML` parses whatever string it's given as HTML — but critically, it does not execute
`<script>` tags the way `document.write()` effectively can. Browsers strip or simply never run script
elements inserted via `innerHTML` assignment, which is a long-standing (if inconsistent) browser
protection against exactly this class of bug. That meant the script-tag payload that worked cleanly
for the earlier reflected-HTML lab would land in the DOM here but never fire. What still works
through `innerHTML` is any HTML element with an inline event handler, since those aren't subject to
the same restriction — the browser happily attaches the `onerror`/`onload` handler and runs it the
moment the element triggers.

## The Exploit

We submitted an image tag with a broken source and an `onerror` handler:

```
GET /?search=%3Cimg%20src%3D1%20onerror%3Dalert(1)%3E
```

Payload: `<img src=1 onerror=alert(1)>`. The `src=1` is not a valid image URL, so the browser fires
its `onerror` event immediately after inserting the element via `innerHTML`, executing our
JavaScript.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution is the same single-step payload: enter `<img src=1 onerror=alert(1)>` into the
search box. Their explanation calls out the same mechanism we relied on — the invalid `src` triggers
an error, which fires `onerror` and runs the alert. No divergence in approach. The only difference is
that their walkthrough types the payload into the search box directly, while we issued the request
via HTTP client and confirmed the resulting DOM execution with a headless browser.

## What This Teaches Us

The practical lesson is that "sanitizing" HTML input isn't a single problem with a single fix —
different DOM sinks have different execution rules, and a payload built for one sink can silently
fail against another even when the underlying vulnerability (attacker-controlled data reaching a
raw-HTML sink) is the same. `innerHTML` blocking `<script>` execution isn't a security control the
application put there on purpose; it's incidental browser behavior, and event-handler attributes
sail right through it. The actual fix is the same as every other DOM XSS lab in this series: don't
feed `location.search` (or any attacker-controlled source) into `innerHTML` unescaped. Use
`textContent` for plain text, or explicitly sanitize/encode before any HTML-parsing sink sees the
value.
