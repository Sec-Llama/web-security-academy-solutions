# Web cache poisoning via an unkeyed query parameter

**Category:** Web Cache Poisoning
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-param

The previous lab excluded the entire query string from the cache key — a blunt, easy-to-spot decision once you know to test for it. This lab is the more realistic version of that mistake: the cache key still includes most of the query string, but a CDN or caching layer strips out specific parameters it assumes are cosmetic, like analytics tracking codes.

## The Target

The home page behaves as a cache oracle: request it with different query parameters and watch which ones cause a cache miss versus which ones silently return the existing cached entry. Most parameters affect the cache key normally. A specific handful don't.

## The Investigation

We fuzzed a candidate list of common analytics and tracking parameters — `utm_source`, `utm_medium`, `utm_campaign`, `utm_content`, `utm_term`, `fbclid`, `gclid`, `dclid`, `msclkid`, and several others — against a cache-busted URL, injecting a canary value into each and checking two things: does the canary reflect in the response, and does it survive a follow-up request that drops the parameter entirely.

`utm_content` was the one that satisfied both conditions. It reflected into the page, and a request without it (but with the same cache buster) still returned the canary — proof this specific parameter never made it into the cache key, even though the rest of the query string clearly does (unlike the previous lab, unrelated parameters *do* cause cache misses here).

## The Exploit

With the vulnerable parameter identified, the payload itself is the same breakout style as the previous lab, just aimed at a single named parameter instead of the whole query string:

```
GET /?utm_content='/><script>alert(1)</script> HTTP/1.1
```

Our exploit function looped this request against the live cache, watching for a miss with the payload present and confirming persistence on subsequent hits:

```python
xss = "'/><script>alert(1)</script>"
r = await client.get(f"{lab_url}/?{excluded_param}={xss}")
```

Because `utm_content` is invisible to the cache key while every other parameter combination on the URL still resolves to the same underlying entry as a clean request, poisoning this one parameter poisons the page for anyone who requests it — including with no `utm_content` at all.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's own solution follows an identical discovery pattern but leans on Param Miner's dedicated "Guess GET parameters" scan rather than fuzzing a candidate list by hand, since Burp's extension has a much larger built-in wordlist of known analytics/tracking parameters than any list we'd hand-maintain. Once the parameter is found, their payload is the same: `?utm_content='/><script>alert(1)</script>`.

The technique is identical end to end. The interesting practical difference is coverage, not method — Param Miner's parameter dictionary is broader than the fixed candidate list our script fuzzes (`UNKEYED_PARAM_CANDIDATES`), which matters more on a real target where the excluded parameter might be something CDN-specific rather than one of the well-known analytics codes. For this lab, our list happened to include the right one on the first pass.

## What This Teaches Us

This is the more common real-world shape of the previous lab's bug: CDNs frequently ship default configurations that strip a known list of tracking parameters from the cache key specifically to avoid cache fragmentation from every unique `fbclid` or `gclid` value creating its own cache entry. That's a sensible default for parameters a backend genuinely ignores — the vulnerability only exists because *this* application reflects `utm_content` back into the page instead of ignoring it. Any parameter a CDN treats as cache-irrelevant is worth testing against the actual application behavior before trusting the CDN's assumption.
