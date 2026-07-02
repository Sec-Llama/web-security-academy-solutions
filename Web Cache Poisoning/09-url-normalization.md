# URL normalization

**Category:** Web Cache Poisoning
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-normalization

Browsers URL-encode dangerous characters before they ever leave the address bar, which is normally a reliable defense against a user accidentally sending raw `<script>` tags in a URL. This lab breaks that defense not by getting a browser to send something unencoded, but by getting the *cache* to treat an encoded URL and its decoded equivalent as the same cache entry — at which point it no longer matters what the victim's browser is willing to send, because we can poison the entry using a channel of our own that isn't bound by browser encoding rules.

## The Target

Requesting a nonexistent path returns a 404 page that reflects the requested path back verbatim: `<p>Not Found: /PATH</p>`. If the path contains raw HTML syntax, it comes back unescaped in that message.

## The Investigation

Testing this from a browser (or from a normal HTTP client) doesn't produce anything interesting, because both automatically percent-encode characters like `"`, `<`, and `>` before they leave — a request for `/random"><script>alert(1)</script>` becomes `/random%22%3E%3Cscript%3Ealert(1)%3C/script%3E` on the wire, and the encoded characters land in the 404 page's reflection harmlessly encoded too.

The cache is a separate piece of infrastructure from the browser, though, and it normalizes URLs for its own purposes — decoding percent-escapes to compare requests for cache-key equivalence. That normalization step doesn't care whether the raw bytes underneath came from a browser's encoding rules or not. If we could get the truly unencoded payload to the server at all, the cache would treat it as equivalent to (and therefore poison the same entry as) the properly encoded version any real browser would send.

The blocker was getting an unencoded path to the server in the first place — every standard HTTP client library (`httpx`, `requests`) applies the same client-side percent-encoding a browser does, precisely because it's spec-correct behavior. We had to bypass client-side encoding entirely by opening a raw TLS socket and constructing the HTTP request line ourselves, byte for byte:

```python
def _raw_get(host: str, path: str, extra_headers: dict = None, use_ssl: bool = True) -> tuple:
    ...
    lines = [f"GET {path} HTTP/1.1", f"Host: {host}", "Connection: close"]
```

Sending `/random"><script>alert(1)</script>` through this raw socket confirmed the payload came back genuinely unescaped in the 404 page's body — no library between us and the wire had a chance to encode it first.

## The Exploit

With raw-socket delivery confirmed, we poisoned the cache with the truly decoded payload:

```
GET /random"><script>alert(1)</script> HTTP/1.1
```

then constructed the properly percent-encoded equivalent of the same path for delivery to the victim:

```python
xss_path = '/random"><script>alert(1)</script>'
encoded_url = f"{lab_url}{quote(xss_path, safe='/')}"
```

The cache on this lab has a short TTL (around 10 seconds), which is tight enough that poisoning and delivering had to happen back-to-back rather than as separate phases — poison via the raw socket, then immediately `POST` the browser-safe encoded URL to the lab's `/deliver-to-victim` endpoint before the entry expired:

```python
if x_cache.lower() == "miss" and has_xss:
    r = await client.post(f"{lab_url}/deliver-to-victim", data={"answer": encoded_url})
```

When the simulated victim's browser requested the properly encoded URL, the cache resolved it to the same normalized key our raw-socket request had poisoned, decoded it back down to the raw payload, and served the `<script>alert(1)</script>` tag intact.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the same reasoning — reflect an unescaped path into a 404 page in Burp Repeater (which, unlike a browser, sends the raw bytes you type without re-encoding them), confirm the same URL requested through a browser doesn't execute because of client-side encoding, then poison the cache through Repeater and immediately load the encoded URL in a browser to demonstrate the normalization makes both requests hit the same entry. Their final step delivers the URL to the victim through the lab's built-in "Deliver link to victim" feature, same as ours.

The real difference is tooling, and it's a meaningful one rather than a cosmetic one: Burp Repeater, like any interception proxy, sends exactly the bytes you put in the editor — it doesn't second-guess or re-encode your request the way an HTTP client library does. That's precisely the property this lab depends on, and it's also precisely what a script built on `httpx` or `requests` doesn't get for free. Raw sockets were the way to reproduce that same "send exactly these bytes" guarantee from a script.

## What This Teaches Us

This is a genuinely different failure mode from every other lab in the series so far — none of the previous vulnerabilities required bypassing a client's own encoding behavior, because the unkeyed input was always something a client sends normally (a header, a cookie, a query parameter). Here, the entire attack surface only exists because the *cache's* URL parser is more permissive than any real browser's request-construction logic, and exploiting that gap meant stepping below the HTTP client library layer entirely. It's a useful reminder that "no browser would ever send that" isn't the same statement as "no request will ever contain that" — an attacker doesn't need a browser to reach the cache, only a way to open a TCP connection to it.
