# Lab: URL-based access control can be circumvented

**Category:** Access Control
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented

Splitting an application across a front-end proxy and a back-end origin server is common
architecture — and it creates a subtle access control trap when the two layers disagree about what
"the URL" is. If the front-end blocks a path but forwards the actual routing decision to the
back-end via a header instead of the request line, the back-end is trusting a value the client
controls just as much as the URL it thinks it replaced.

## The Target

Requesting `/admin` directly returns a block response. The response itself is unusually bare —
no styling, no application chrome — which reads like it's coming from a lightweight front-end
gatekeeper rather than the full application.

## The Investigation

A block response that looks structurally different from the rest of the site's pages is a signal
worth following: it suggests two separate systems are involved, one that enforces the block and one
that renders everything else. Platforms fronted this way sometimes support routing override
headers like `X-Original-URL` or `X-Rewrite-URL`, intended for legitimate use cases (rewrites, load
balancer path preservation) but capable of telling the back-end to route somewhere different from
what the front-end's own path-matching logic saw.

We tested both override headers against the base path:

```python
headers_to_try = [
    ("X-Original-URL", target_path),
    ("X-Rewrite-URL", target_path),
]
resp = client.get(base_url, headers={header_name: header_val})
```

```
GET /?username=carlos HTTP/1.1
X-Original-URL: /admin/delete    -- Front-end sees /, back-end routes to /admin/delete
-- Key: Query params go on the real URL, X-Original-URL overrides the path only
```

Requesting `/` (a path the front-end has no reason to block) while setting `X-Original-URL: /admin`
returned the actual admin panel content — confirmation that the back-end was routing based on the
header, and that the front-end's block on `/admin` only inspected the literal request line, never
the header that determined where the request actually went.

## The Exploit

With the override confirmed, we combined it with the query parameter needed to target `carlos`,
keeping the query string on the real request path (since `X-Original-URL` only overrides the path
component, not the parameters) and pointing the header at the delete action directly:

```
GET /?username=carlos HTTP/1.1
X-Original-URL: /admin/delete
```

```python
resp = client.get(
    f"{base}/?username=carlos",
    headers={"X-Original-URL": "/admin/delete"}
)
```

The response confirmed the deletion, and the lab solved on the next check.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the identical technique: try `/admin` and get blocked by what looks
like a front-end system; send `/` with `X-Original-URL: /invalid` to confirm the back-end is
processing that header at all (a "not found" response proves it); switch the header value to
`/admin` and confirm access; then add `?username=carlos` to the real query string and change
`X-Original-URL` to `/admin/delete` to perform the deletion. This is the same header, the same
routing-layer confusion, and the same final request shape we used.

The one procedural difference is that PortSwigger's walkthrough includes an explicit sanity-check
step — requesting an invalid path via the header first, specifically to prove the back-end is
reading it at all before trusting it for anything sensitive. Our script skipped that intermediate
confirmation and validated the bypass directly against `/admin`, since a successful, non-blocked
response to that request already proves the same thing the sanity check would have.

## What This Teaches Us

The access control failure isn't in either system individually — the front-end's block logic and
the back-end's admin panel are both, in isolation, doing something defensible. The gap opens because
they disagree about which piece of the request is authoritative for routing, and the piece the
back-end trusts (`X-Original-URL`) is one the front-end never validates before forwarding it
untouched. Any architecture that lets one layer make security decisions based on data another layer
treats as just plumbing needs both layers to agree on the source of truth, or the weaker one becomes
the real perimeter.
