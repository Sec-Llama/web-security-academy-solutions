# Web cache poisoning via a fat GET request

**Category:** Web Cache Poisoning
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-fat-get

Most people don't think of `GET` requests as carrying a body — the HTTP spec doesn't forbid it, but browsers never send one, so it's easy to assume no server-side code path ever reads one either. Some frameworks disagree, and that mismatch between "what the cache expects a GET to look like" and "what the back-end will actually process" is this lab's entire vulnerability.

## The Target

The same JSONP-style `callback` import from the previous lab — `/js/geolocate.js?callback=setCountryCookie` — reused here to demonstrate a different route to the same kind of parameter smuggling.

## The Investigation

Where the parameter-cloaking lab exploited a semicolon-parsing discrepancy, this one exploits a request-method discrepancy: the application accepts a request body on a `GET` request, and when a body parameter and a URL parameter share the same name, the body value takes precedence in what the back-end actually processes — while the cache key is built exclusively from the URL, with no visibility into whatever the request body contains.

We confirmed this by sending the JSONP request with `callback=setCountryCookie` on the URL (the value the cache keys on) and a body of `callback=<canary>` (application/x-www-form-urlencoded), adding an `X-HTTP-Method-Override: POST` header to make sure the request would actually be treated as carrying a meaningful body rather than silently ignored:

```
GET /js/geolocate.js?callback=setCountryCookie HTTP/1.1
Content-Type: application/x-www-form-urlencoded
X-HTTP-Method-Override: POST

callback=<canary>
```

The canary showed up in the response in place of `setCountryCookie` — the body parameter won.

## The Exploit

With the priority confirmed, swapping the canary for a real payload was direct:

```python
poison_url = f"{jsonp_url}?callback=setCountryCookie"
body = "callback=alert(1)"
headers_override = {
    "Content-Type": "application/x-www-form-urlencoded",
    "X-HTTP-Method-Override": "POST",
}
r = await client.request("GET", poison_url, content=body, headers=headers_override)
```

The response body executes `alert(1)(...)` as the JSONP callback invocation, and because the URL — the part the cache actually keys on — never changed from the clean `callback=setCountryCookie` value, this poisoned response gets stored under the exact same cache key every page's script import resolves to. We looped the request until a cache miss confirmed the poison stuck, then let the sustained re-poison cycle carry it through to the lab's simulated visitor.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the identical technique: send `GET /js/geolocate.js?callback=setCountryCookie` with a body containing a duplicate `callback` parameter, observe that the body value controls the function name invoked while the cache key derives only from the URL parameter, and poison with `alert(1)` as the body's callback value. Our approach matched this exactly — this is one of the few labs in the series where our automated solve and the official manual one aren't just conceptually the same technique, they're functionally the same request.

The only addition on our side was defensive rather than substantive: trying the request both with and without `X-HTTP-Method-Override: POST` set, since not every server implementation honors a GET request body without that hint, and it costs nothing to attempt both.

## What This Teaches Us

"Fat GET" requests exist because some frameworks are permissive about what counts as a valid request rather than because anyone intended browsers to send bodies on `GET`. That permissiveness becomes a cache poisoning primitive the moment a caching layer assumes — reasonably, by the letter of the HTTP spec — that a `GET` request's identity is fully captured by its URL and headers. PortSwigger's own guidance on this points at a genuinely practical mitigation: reject `GET` requests that arrive with a body at the edge, before they ever reach a cache or an application server capable of reading one. If nothing legitimate in your stack sends fat GETs, there's no reason to accept them.
