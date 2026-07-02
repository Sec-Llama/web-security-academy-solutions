# Exploiting HTTP request smuggling to perform web cache deception

**Category:** HTTP Request Smuggling
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/request-smuggling/exploiting/lab-perform-web-cache-deception

Cache poisoning stores an attacker's malicious content for everyone else to receive. Cache deception runs in the opposite direction: it stores a *victim's* sensitive response under a URL the attacker can later request themselves, turning the shared cache into an exfiltration channel rather than a distribution channel for malicious content.

## The Target

The application's account page includes the user's private API key, and — critically — the response has no anti-caching headers set. That alone isn't exploitable under normal circumstances, since `/my-account` isn't itself a cacheable-by-default path. What makes it exploitable is the combination with request smuggling: if we can get the back-end to serve the account page's contents in response to a request whose URL the front-end's cache treats as a static resource, the cache stores someone else's private page under a static-looking URL.

## The Investigation

The technique here is a variant of the smuggling pattern used for capturing users' requests, but instead of smuggling a complete standalone request, we smuggle a deliberately *incomplete* one. Rather than send `GET /my-account HTTP/1.1\r\n\r\n` as a finished request, we send it without the terminating blank line, ending instead in a dangling header:

```
GET /my-account HTTP/1.1
X-Ignore: X
```

Because this request is incomplete, the back-end keeps waiting for more headers before it can process it — and the next real user's request line, whatever it is, gets absorbed straight into the value of `X-Ignore` rather than starting a fresh request of its own. If that next real request happens to be a victim's browser requesting a static resource (which carries their `Cookie` header along automatically), the back-end ends up processing `GET /my-account` *using the victim's session*, and the response — their account page, complete with their real API key — gets cached by the front-end under the URL the victim actually requested.

Using `X-Ignore:` specifically, rather than letting the follow-up request's own `Host` header collide with ours, sidesteps a duplicate-`Host`-header 400 error that a more naive incomplete-request construction runs into.

## The Exploit

```
POST / HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 42
Transfer-Encoding: chunked

0

GET /my-account HTTP/1.1
X-Ignore: X
```

We fired this smuggle repeatedly, then checked every static resource path on the site for the string "Your API Key" appearing in a response that should have been a plain CSS or JS file. Because the timing depends on a real victim's request landing on the poisoned connection at the right moment, this isn't guaranteed on the first attempt — we kept re-sending the smuggle and re-checking the static resources until one of them came back containing the leaked account page content instead of its normal static file body.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution uses the identical incomplete-request smuggling technique:

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 42
Transfer-Encoding: chunked

0

GET /my-account HTTP/1.1
X-Ignore: X
```

— an exact match, down to the `Content-Length: 42` value. Their walkthrough then instructs repeating the request a few times, loading the home page in an incognito window to trigger a victim-like static-resource request, and searching Burp's site map for "Your API Key" appearing anywhere it shouldn't. That's functionally the same brute-force verification loop our script ran, just performed with Burp's built-in search feature over manually captured traffic rather than an automated scan of every static path. The core technique is identical in both cases — this is one of the labs in the series where the "right" payload has essentially one obvious construction once you understand the incomplete-request trick, so there was no meaningful room for a different technical approach, only a different way of driving the same requests.

## What This Teaches Us

Cache deception is a reminder that "no anti-caching headers" is a real risk even on pages that were never intended to be cached, because the vulnerability isn't really about the account page — it's about a shared cache that can be tricked into storing a response under a URL it never actually corresponds to. Combined with request smuggling's ability to make the back-end process one user's request using another user's session, this turns a page that "just happens" to lack `Cache-Control: no-store` into a mechanism for silently exfiltrating every visitor's private data to anyone who knows to check the right static-looking URL. The fix is two-layered, same as the cache poisoning lab: close the smuggling vector, and set explicit no-store headers on any response containing session-scoped or sensitive data, regardless of whether the path "looks" cacheable.
