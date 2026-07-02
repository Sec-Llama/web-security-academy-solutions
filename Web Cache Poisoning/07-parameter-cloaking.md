# Parameter cloaking

**Category:** Web Cache Poisoning
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-param-cloaking

An unkeyed parameter that reflects directly into the page, like the previous lab, is the easy version of this bug. This lab asks a harder question: what happens when the unkeyed parameter *doesn't* reflect anything by itself, but the cache and the back-end disagree about where one parameter ends and another begins? That disagreement turns an inert, unkeyed parameter into a smuggling channel for a parameter that very much matters.

## The Target

The application imports a JSONP-style script — `/js/geolocate.js?callback=setCountryCookie` — on every page, where the `callback` query parameter names the JavaScript function the endpoint's response invokes. `callback` itself is a keyed parameter: changing it changes the cache entry, so poisoning it directly the way earlier labs poisoned a reflected value doesn't work — you can control your own response, but not one served to anyone else.

## The Investigation

`utm_content` was, once again, unkeyed — but this time, setting it to a canary value produced no visible reflection at all. On its own, `utm_content` is dead weight: unkeyed, but inert.

The interesting behavior showed up once we combined it with a semicolon. The back-end here runs on Rails, which historically treats `;` as an additional parameter delimiter alongside `&` — a legacy behavior most modern frameworks have dropped, but Rails still honors it. That meant a request like:

```
GET /js/geolocate.js?callback=setCountryCookie&utm_content=x;callback=alert(1)
```

gets parsed two different ways by two different components. The cache's parser sees `utm_content=x;callback=alert(1)` as a single opaque value assigned to `utm_content` — it doesn't know about the semicolon convention, so as far as the cache key is concerned, this request is indistinguishable from the plain `callback=setCountryCookie` request, because `utm_content` (whatever value it holds) is already excluded from the key. Rails, on the other hand, splits on the semicolon and sees a second, later `callback=alert(1)` parameter — and because later parameters win in Rails' parameter parsing, the back-end actually invokes `alert(1)` as the callback function name.

## The Exploit

We located the JSONP import path from the page markup, then rebuilt its query string from scratch to construct the cloaked request:

```python
base_jsonp = jsonp_url.split("?")[0]
poison_url = (f"{base_jsonp}?callback=setCountryCookie"
              f"&utm_content=x;callback=alert(1)")
```

Stripping any pre-existing query string from the JSONP URL before rebuilding it mattered — leaving a stray, duplicate `callback` parameter in there confuses which value the cache actually keys on and breaks the cloaking. With the URL built correctly, we looped the request against the live cache:

```
GET /js/geolocate.js?callback=setCountryCookie&utm_content=x;callback=alert(1) HTTP/1.1
```

Once a cache miss showed the poisoned response stored with `alert(1)` as the invoked function, the response body reads as executable JavaScript calling `alert(1)(...)` wherever the page imports this resource — and since the cache key still matches the plain `callback=setCountryCookie` URL every page actually requests, every page importing `geolocate.js` inherits the poisoned function call.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution walks the identical chain: confirm `utm_content` is unkeyed but doesn't reflect on its own, use the semicolon delimiter (or Param Miner's dedicated "Rails parameter cloaking scan," which automates the discovery) to smuggle a second `callback` parameter past the cache's parser while the Rails back-end honors it, and poison the JSONP import with `callback=alert(1)`. Same root cause, same payload shape, same delimiter.

The one place our own build diverged from a naive first attempt — worth calling out because it's a real bug we hit and fixed, not a design choice — was in how the poison URL got constructed. Building it by appending to whatever query string the JSONP `src` attribute already had risked leaving a duplicate, already-keyed `callback` parameter in the URL, which broke the cloaking silently (the cache would key on the *first* `callback`, not realize `utm_content` was doing anything interesting, and the poison just wouldn't stick). Rebuilding the query string from the bare path first fixed it. This is a small, mechanical difference from PortSwigger's Repeater-driven walkthrough, but it's exactly the kind of thing that only shows up once you're generating the request programmatically instead of hand-editing one already-formed request in a GUI.

## What This Teaches Us

Parameter cloaking is a parsing-discrepancy bug, not a reflection bug — nothing about `utm_content` itself is dangerous, and no payload in `utm_content` ever appears anywhere in the response. The danger is entirely in the disagreement between how the cache tokenizes a query string and how the framework behind it does, and semicolon-as-delimiter is just one specific, well-known instance of that disagreement (Ruby/Rails' historic behavior). Any place a caching layer and an application framework parse the same raw bytes with different rules is a candidate for this same class of smuggling, whether the disagreement is about delimiters, parameter-name case sensitivity, or duplicate-parameter precedence.
