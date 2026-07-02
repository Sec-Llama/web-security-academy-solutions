# Web cache poisoning via an unkeyed query string

**Category:** Web Cache Poisoning
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-query

The first four labs in this series all abused *design* flaws — headers and cookies the application trusts and reflects, that just happen not to be part of the cache key. This lab is the first in the series' implementation-flaw half: the vulnerability isn't a header the developer chose to trust, it's a caching layer that made a performance decision — strip the entire query string from the cache key — without checking whether the query string ever reaches the page itself.

## The Target

Requests to the home page with an arbitrary query string return normally, and the page includes a `<link rel="canonical">` tag that echoes the request's own query string back into its `href` attribute — a common SEO pattern for telling search engines the canonical form of a URL.

## The Investigation

We confirmed the query string was reflected by requesting `/?test=REFLECTED_CHECK` with an `Origin` header carrying a random value as a cache buster (a query-string-based buster wouldn't help us here, for reasons that become obvious once you realize the whole query string is what's under test — `Origin` is a header that *is* kept in this cache's key, so it's safe to vary without touching the entry we're trying to observe). `REFLECTED_CHECK` came back inside the canonical link tag:

```html
<link rel="canonical" href='//HOST/?test=REFLECTED_CHECK'/>
```

The real question was whether the cache key includes the query string at all, or just the path. Testing `GET /` against `GET /?anything=x` and comparing cache behavior confirmed it: the entire query string is excluded from the cache key, meaning `GET /` and `GET /?evil=payload` are treated as the exact same cache entry.

## The Exploit

Since the query string only needs to break out of a single-quoted HTML attribute, the payload was straightforward:

```
GET /?evil='/><script>alert(1)</script> HTTP/1.1
```

which turns the canonical tag into:

```html
<link rel="canonical" href='//HOST/?evil='/><script>alert(1)</script>'/>
```

We sent this directly against the production cache entry (no cache buster this time — the entire point is to poison the *real* entry that `GET /` resolves to), looping the request and checking each response for a cache miss with the payload present, confirming a subsequent hit still carried it:

```python
xss = "'/><script>alert(1)</script>"
r = await client.get(f"{lab_url}/?evil={xss}")
```

Because `GET /` shares a cache key with every variant of `GET /?anything`, poisoning any one of them poisons the clean URL every visitor actually requests. We kept the poison loop running until the lab's simulated visitor picked up the payload and the lab solved.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the same conclusion through the same reasoning: use the home page as a cache oracle, add an arbitrary query parameter and observe the cache still returns a hit (proving the query string is unkeyed), use `Origin` as a safe cache buster during recon, find the query string reflected in the canonical tag, and poison with the identical `'/><script>alert(1)</script>` breakout. They also point out a useful debugging tool we didn't need but is worth knowing about: sending `Pragma: x-get-cache-key` to the target returns the literal cache key the server used for that request, which turns "is this parameter keyed?" from an inference into a direct answer.

This is a case of full technique convergence — the vulnerability only supports one sensible exploitation path, so both approaches land on the same payload. The difference is again mechanical: Burp Repeater with manual `X-Cache` header inspection versus a scripted poison-and-verify loop.

## What This Teaches Us

"Exclude the query string from the cache key" is a completely reasonable-sounding performance optimization in isolation — plenty of query parameters genuinely don't change page content (tracking codes, referral IDs) and caching each variant separately would waste cache capacity for no benefit. The mistake here is applying that exclusion uniformly without verifying the query string never reaches the rendered page. The fix PortSwigger's own material recommends is the direct one: either key the cache on the full query string, or strip/encode it before it's ever reflected back into the response — but not both left unaddressed at once, which is what actually happened here.
