# Web cache poisoning with an unkeyed header

**Category:** Web Cache Poisoning
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-header

James Kettle's original "Practical Web Cache Poisoning" research turned a category most people dismissed as a curiosity into one of the more consequential web bug classes of the last decade — a single poisoned cache entry means the payload doesn't hit one victim, it hits every visitor who requests that URL until the entry expires or gets overwritten. This lab is the introductory case: a header that shapes the page but never touches the cache's notion of "what makes this request unique."

## The Target

The lab serves a normal-looking site over `GET /`. Nothing about a browser's default request reveals anything unusual — the interesting behavior only shows up once you start adding headers the application wasn't expecting a normal visitor to send.

## The Investigation

The starting hypothesis for any cache poisoning target is simple: find an input that changes the response but isn't part of the cache key. We probed with a canary value in a candidate header and a cache-busting query parameter to avoid contaminating the real cache entry during recon:

```
GET /?cb=<random> HTTP/1.1
X-Forwarded-Host: test-canary.com
```

`test-canary.com` came back reflected in the response. That's the first half of the confirmation — the header affects the page. The second half is proving it's *unkeyed*: request the same cache-busted URL again without the header, and if the canary is still present, the cache stored the poisoned version and is now serving it regardless of the header. That's exactly what happened, which told us `X-Forwarded-Host` sits outside this cache's key entirely.

Looking at where the value landed in the markup pointed at a resource-import context — the header value builds an absolute URL used to pull in a JavaScript file, the classic shape for this vulnerability class (`<script src="//X-FORWARDED-HOST-VALUE/resources/js/tracking.js">`).

## The Exploit

Rather than standing up a hosted JavaScript file, we broke out of the `<script>` tag directly inside the header value:

```
X-Forwarded-Host: "></script><script>alert(document.cookie)</script>
```

This closes the tag the header value was being written into and opens a fresh one containing our own payload — no separate file needed. Our lab wrapper sends this repeatedly against the cached URL until it observes a cache miss (confirming the poisoned response was just stored), then issues a clean request to confirm the payload persists without the header attached:

```python
xss_payload = '"></script><script>alert(document.cookie)</script>'
poisoned = await poison_via_header(lab_url, "X-Forwarded-Host", payload=xss_payload)
```

The cache on this lab expires roughly every 30 seconds, so a single successful poison isn't enough — the loop keeps re-sending the poisoned request so a fresh copy is sitting in the cache whenever the lab's simulated visitor happens to load the page. Once that landed, the lab flagged as solved.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's own solution stores `alert(document.cookie)` on an exploit server at `/resources/js/tracking.js`, then sets `X-Forwarded-Host` to that exploit server's domain so the poisoned response's resource-import URL resolves to attacker-controlled infrastructure — a full external file rather than an inline breakout.

Both approaches exploit the identical root cause: the header value is written unsanitized into a resource-import URL, and that header isn't part of the cache key. Where they differ is delivery. The exploit-server approach works in *any* reflection context, including ones where the value is only ever used as a hostname and never lands somewhere that permits tag injection. Our direct breakout is faster to set up (no external file to host or point to) but only works because this particular lab's reflection context happens to allow a `"></script>` escape. For a lab this specific, both land on the same outcome; the exploit-server pattern is the one worth defaulting to on a real target where you can't first confirm the reflection context permits inline breakout.

## What This Teaches Us

The vulnerability isn't the header itself — `X-Forwarded-Host` is a legitimate mechanism for reverse proxies to tell an application what hostname the client actually requested. The bug is trusting that value enough to write it unsanitized into HTML while never including it in the cache key that decides who else receives the resulting response. Either half of that mistake alone is comparatively low severity: an unkeyed header with no unsafe reflection is inert, and an unsafe reflection with a keyed header only ever affects the single requester who sent it. It's the combination that turns a one-off reflected XSS into a stored payload served to every subsequent visitor of a cached URL.
