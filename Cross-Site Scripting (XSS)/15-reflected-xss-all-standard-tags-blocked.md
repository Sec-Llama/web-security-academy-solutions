# Reflected XSS into HTML context with all tags blocked except custom ones

**Category:** Cross-Site Scripting (XSS)
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-all-standard-tags-blocked

The previous lab's filter let one real HTML tag slip through a blocklist; this one goes further and
blocks every standard tag the filter recognizes — but the filter's definition of "recognizes" is the
gap. It's checking submitted markup against a list of known HTML tag names, and a tag name the filter
has simply never heard of doesn't get flagged as suspicious, even though browsers will still treat it
as a valid (if meaningless) custom element and still process its attributes, including event
handlers.

## The Target

Same search functionality, now with a filter aggressive enough to reject `<body>`, `<svg>`, `<img>`,
and every other standard tag we tried.

## The Investigation

Once real HTML tags were confirmed blocked across the board, we tested a made-up tag name —
`<xss>` — and it went through untouched. That's the whole mechanism: the filter's blocklist is a
finite, hardcoded set of known tag names, and it has no concept of "reject anything that isn't on an
allow-list," so any string shaped like a tag but not present in that blocklist passes straight
through, attributes and all. Browsers don't require a tag name to be a real HTML element to parse its
attributes and fire its events — an unrecognized tag still gets attached to the DOM as an unknown
(but valid) custom element, and `autofocus`/`onfocus` still behave normally on it.

We also confirmed a delivery constraint here: `autofocus` doesn't reliably fire inside an `<iframe>`
the way it does on a top-level page load, so simply embedding the payload URL in an iframe (as we did
for earlier tag-restricted labs) wasn't going to trigger it. The reliable path was a full top-level
navigation to the payload URL.

## The Exploit

We built a custom tag with autofocus and an onfocus handler:

```
<xss id=x onfocus=alert(document.cookie) tabindex=1>#x
```

Delivered via the exploit server as a full-page redirect rather than an iframe, so `autofocus`-style
focus behavior fires correctly on top-level navigation:

```html
<script>location='https://LAB-ID.web-security-academy.net/?search=%3Cxss%20id%3Dx%20onfocus%3Dalert(document.cookie)%20tabindex%3D1%3E#x';</script>
```

The `#x` fragment causes the browser to jump to and focus the element with `id=x` as soon as the page
loads, which fires the custom tag's `onfocus` handler and executes the alert — no user interaction
required.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution delivers essentially the same payload through the exploit server as a
`location =` redirect:
`<xss id=x onfocus=alert(document.cookie) tabindex=1>#x`, explaining that the fragment focuses the
custom element on load, firing `onfocus`. This matches our approach exactly, including the redirect
delivery mechanism rather than an iframe — both independently landed on the same fix for the
autofocus/iframe timing issue. No technique divergence here. The difference, consistent with the rest
of this series, is that their walkthrough pastes the exploit code into the exploit server's web form
manually, while we posted the same body to the exploit server's endpoints via HTTP client.

## What This Teaches Us

This lab is the clearest illustration in the series so far of why blocklists fail structurally rather
than just accidentally: the filter isn't missing one obscure tag, it's missing an entire open-ended
category — every tag name that doesn't happen to appear in its hardcoded list, which by definition
includes every name a filter's author didn't think to add. Browsers treating unrecognized tags as
valid custom elements (complete with working attributes and events) means the attacker's search space
for a bypass is effectively unbounded, while the defender's blocklist is always finite. The fix, as
with the previous lab, is the same structural correction: allow-list a small set of genuinely safe
tags with no event-handler attributes permitted, rather than trying to enumerate every dangerous tag
name that could ever exist.
