# Reflected XSS with some SVG markup allowed

**Category:** Cross-Site Scripting (XSS)
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-some-svg-markup-allowed

A tag blocklist only works if it lists every dangerous tag, and SVG has always been the hardest
category to enumerate completely — it's a huge specification with animation elements most filter
authors never think to check. This lab is a clean demonstration of that gap: the site blocks the
obvious injection vectors but leaves a corner of SVG markup completely open.

## The Target

The now-familiar blog search box, reflecting the `search` parameter back into the page. A standard
probe like `<img src=1 onerror=alert(1)>` gets blocked outright, which told us the application is
filtering common tags rather than encoding output.

## The Investigation

With the obvious tags rejected, the question was which tags and which event attributes the filter
actually lets through. From accumulated experience with this application's filtering style across
the earlier labs in the series, SVG's `<animatetransform>` element with an `onbegin` handler was
already a known-good vector for this kind of blocklist gap: `animatetransform` isn't part of most
filter authors' mental model of "dangerous tags" the way `<script>` or `<img onerror>` is, and its
`onbegin` attribute fires as soon as the animation starts — no click, no focus, no user interaction
needed.

## The Exploit

We sent the payload directly:

```
<svg><animatetransform onbegin=alert(1)>
```

as a `search` parameter value, and loaded the resulting URL in a browser with the lab's session
cookie attached:

```
GET /?search=%3Csvg%3E%3Canimatetransform%20onbegin%3Dalert(1)%3E
```

The tag passed the filter untouched, the animation began immediately on page load, and `onbegin`
fired `alert(1)`.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's official solution reaches the same payload but documents the discovery process we
skipped: submit `<>` as the search term with a payload position between the brackets, paste the
full XSS cheat sheet's tag list into Burp Intruder, and fire the attack. The results show every tag
returning a `400` except `<svg>`, `<animatetransform>`, `<title>`, and `<image>`. A second Intruder
pass, this time fuzzing event attributes on `<svg><animatetransform%20§§=1>`, isolates `onbegin` as
the one that survives. The final confirmation payload is byte-for-byte identical to ours:
`<svg><animatetransform onbegin=alert(1)>`.

The difference here isn't in tooling — it's in how we got to the payload. PortSwigger's walkthrough
treats the filter as an unknown quantity and systematically brute-forces it with Intruder across the
full cheat sheet, which is the right approach when you're seeing this filter for the first time. We
already knew `<animatetransform onbegin=...>` as an effective SVG bypass from working through this
application's filtering patterns in prior labs in the series, so we went straight to it rather than
re-running the fuzzing pass. The lab doesn't care how you arrive at the payload, only that it works —
but it's worth being honest that our path assumed prior knowledge the official walkthrough builds
from scratch.

## What This Teaches Us

SVG is a large, animation-capable format, and treating it as "safe markup" because it isn't
`<script>` is a common and costly assumption. `<animatetransform>` and its siblings
(`<animate>`, `<set>`) can drive attribute values and fire on lifecycle events like `onbegin` without
any user interaction, which makes them just as dangerous as the classic `<img onerror>` vector once
they're allowed through. A blocklist built by enumerating "known bad" tags will always miss corners
like this; the durable fix is the same one every lab in this series arrives at — allow-list a small,
genuinely safe set of tags and strip all event-capable attributes regardless of which tag they're
attached to.
