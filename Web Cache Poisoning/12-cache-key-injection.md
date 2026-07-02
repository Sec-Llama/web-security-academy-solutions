# Cache key injection

**Category:** Web Cache Poisoning
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-cache-key-injection

This is the most heavily chained lab in the series — four separate, individually unremarkable flaws, none of which produces anything on its own, that only add up to an exploitable primitive once combined in the right order. It's also the first lab where we had to reach for a debugging header PortSwigger built specifically for this vulnerability class, because guessing at cache-key structure by trial and error stops being tractable once the key itself becomes attacker-influenced.

## The Target

Two endpoints matter here: `/login`, which redirects based on a `lang` query parameter, and `/js/localize.js`, a script imported by the login page that accepts `lang` and `cors` query parameters.

## The Investigation

Four independent issues had to be identified before any of them meant anything:

**1. A flawed `utm_content`-stripping regex on `/login`.** The cache excludes `utm_content` from the key, same as earlier labs — but the regex doing the stripping expects `utm_content` to be preceded by `&` or the start of the query string. Using `?` instead of `&` immediately before it (`/login?lang=en?utm_content=...`) means the regex's assumption doesn't hold, and everything from that `?utm_content=` onward gets folded into the *value* of `lang` as far as the cache key is concerned — while the back-end parses it completely differently, as an actual separate parameter.

**2. Client-side parameter pollution on `/login/`.** The login page imports `/js/localize.js?lang=LANG_VALUE&cors=0`, building that import URL from the `lang` value without URL-encoding it first. Anything we get into `lang` server-side gets carried, unencoded, into this script-import URL.

**3. Response header injection via `Origin` on `/js/localize.js`.** When `cors=1` is set, this endpoint reflects the `Origin` header into an `Access-Control-Allow-Origin` response header — and it URL-decodes `%0d%0a` sequences in that header *before* reflecting them, which means a request `Origin` value containing encoded CRLF sequences becomes literal header injection in the response. Injecting `Content-Length: 8` ahead of a body of `alert(1)` truncates everything the server actually intended to send after those first 8 bytes, leaving just `alert(1)` as the effective response.

**4. The cache key injection itself.** Sending `Pragma: x-get-cache-key` back to the server returns the literal cache key it used for the request — this lab exposes that debug header directly, and it's what made confirming the key's actual delimiter-based structure (`/path?params$$origin=VALUE$$`) tractable rather than guesswork. Because the key is built by concatenating components with a `$$` delimiter, and the URL itself isn't excluded from what can land inside that structure, injecting our own `$$origin=VALUE$$` sequence into the URL lets us align a victim's URL-derived cache key with an attacker-controlled, header-derived cache key of our own choosing.

## The Exploit

Getting the encoding right across four chained flaws was the hardest part of this lab — several encoding layers had to be exactly right or the poison silently failed to align. The two poisoning requests, fired concurrently on every cycle:

```python
origin_val = f"x%0d%0aContent-Length:%208%0d%0a%0d%0aalert(1){d}{d}{d}{d}"
utm_val = (
    f"x%26cors=1%26x=1{d}{d}origin=x%250d%250aContent-Length:%208"
    f"%250d%250a%250d%250aalert(1){d}{d}%23"
)

r1, r2 = await asyncio.gather(
    client.get(f"{host}/js/localize.js?lang=en?utm_content=z&cors=1&x=1",
               headers={"origin": origin_val}),
    client.get(f"{host}/login?lang=en?utm_content={utm_val}"),
)
```

(`d = "$"` — the literal cache-key delimiter character.) A handful of encoding details turned out to matter enough to break the whole chain if they were wrong: the `=` and `:` characters in the second request's URL had to stay literal rather than percent-encoded, or the two requests' cache keys wouldn't align; `%20` (single-encoded space) had to stay single-encoded for the same reason; a trailing `%23` (URL fragment marker `#`) truncates the unwanted `&cors=0` off the poisoned script-import URL once it's reflected client-side; and `%250d%250a` — *double*-encoded CRLF — was necessary in the `/login` request specifically because that value passes through one layer of server-side decoding before it ever reaches the header-injection sink, so it needs to still be encoded once it gets there.

This lab also required HTTP/2 specifically (the `Origin` header injection technique behaves differently over HTTP/1.1, and per the HTTP/2 spec, header names including `Origin` must be sent lowercase), and both poisoned entries share a similar TTL (~35 seconds) to the previous lab's dual-poison requirement, so both requests were kept alive on the same loop.

One operational trap worth naming directly: checking whether the lab had solved by following the redirect chain on `/login` through the target itself overwrites the very cache entry we'd just poisoned — verification has to happen through the lab's own status indicator or a browser, never by re-requesting the poisoned URL with redirects enabled.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution walks through the same four components in the same order: the flawed `utm_content` regex on `/login`, the unencoded `lang` value flowing into the `localize.js` import, `Origin`-based CRLF header injection on `cors=1` requests, and using `Pragma: x-get-cache-key` to confirm the `$$`-delimited key structure before constructing the two aligned poisoning requests.

The technique matches ours exactly — this lab, like the request-tunnelling labs elsewhere in the Academy, really only supports the one intended exploitation path once all four components are identified, so there's no meaningful divergence to explain. What's worth naming honestly is how much of "the same technique" undersells the actual difficulty gap between reading PortSwigger's numbered solution steps and independently landing on the correct encoding at each of the several layers involved. Getting single- versus double-encoding wrong at any one of the several points in this chain produces a request that looks nearly identical but simply doesn't poison anything — no error, no signal, just silence. `Pragma: x-get-cache-key` earns its place as the one piece of infrastructure PortSwigger built specifically to make this lab solvable without pure trial and error.

## What This Teaches Us

Every individual flaw in this chain is, on its own, either harmless or of marginal interest: a slightly-too-permissive regex, one unencoded value flowing into a URL, a header reflected without full sanitization, and a cache key with a documented (even debuggable) internal structure. None of them alone leaks data or executes code. It's specifically the fact that the cache key's own construction is influenceable by attacker input — not just which components are excluded from it, as in every earlier implementation-flaw lab, but the literal *shape* of the key itself — that turns four minor issues into a working exploit chain. A cache key built by string concatenation with a fixed delimiter is only as safe as the guarantee that no input reaching it can ever contain that delimiter, and here, nothing was actually enforcing that guarantee anywhere along the four-flaw chain.
