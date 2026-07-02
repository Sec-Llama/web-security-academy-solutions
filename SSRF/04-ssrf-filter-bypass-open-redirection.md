# SSRF with filter bypass via open redirection vulnerability

**Category:** Server-Side Request Forgery (SSRF)
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection

Not every SSRF filter can be beaten with encoding tricks. Sometimes the application restricts the
vulnerable parameter so tightly that no amount of obfuscation gets an absolute URL past it — and the
way in turns out to run through a completely different, unrelated feature entirely.

## The Target

The same stock-check feature as the previous labs, but this time `stockApi` is restricted to relative
paths on the local application only — any attempt to point it at an external host or IP is rejected
outright, with no blacklist-style string filtering to bypass. Elsewhere in the same application, a
"next product" link on the product page sends:

```
GET /product/nextProduct?currentProductId=1&path=/product?productId=2
```

and issues a redirect to whatever `path` contains.

## The Investigation

With `stockApi` locked down to relative paths, feeding it an absolute URL like
`http://192.168.0.12:8080/admin` directly fails immediately — there's no encoding layer to hide the
host behind, because the restriction isn't inspecting the string for blocked substrings, it's
rejecting anything that isn't already a relative path on the same app. That's a narrower attack
surface than the blacklist in the previous lab, but the `path` parameter on `/product/nextProduct`
told us something useful: it takes whatever URL it's given and issues an HTTP redirect to it, without
validating that the destination is internal to the application at all. That's an open redirect — and
an open redirect on a domain the SSRF filter already trusts is exactly the kind of building block that
turns a relative-path restriction into an absolute bypass. If `stockApi` is only checking that the
*literal string it receives* looks like a relative path, then handing it the open redirect's own path
satisfies that check, while the actual destination the server ends up fetching is decided entirely by
where the redirect points.

## The Exploit

Our `exploit_ssrf_open_redirect()` function builds exactly this chain — the vulnerable parameter's
value becomes the open redirect endpoint with the real internal target appended as its `path` query
string:

```python
chain_url = f"{redirect_endpoint}{internal_target}"
r = client.request(method, url, data={param_name: chain_url})
```

Applied to this lab, with the internal admin host at `192.168.0.12:8080` (a fixed target for this
lab, unlike Lab 2's IP sweep):

```
stockApi=/product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin
```

`stockApi` still reads as a relative path on the local application — the filter has nothing to object
to. But the application follows that path to `/product/nextProduct`, which reads its own `path`
parameter and issues a redirect to `http://192.168.0.12:8080/admin`, and the stock-checker's HTTP
client follows that redirect automatically. The response came back as the full admin interface.

Reading the delete link out of the response (again handling the absolute-URL `href` quirk from Lab 2)
and re-running the same chain with the delete path appended completed the exploit:

```
stockApi=/product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin/delete?username=carlos
```

The lab's solved check confirmed carlos was deleted.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows an identical chain, down to the same internal target host —
`http://192.168.0.12:8080/admin` — and the same redirect endpoint,
`/product/nextProduct?path=...`. Their write-up frames the discovery in the same order we found it:
try tampering with `stockApi` directly and see that absolute hosts are rejected, then notice that
"next product" places an unvalidated `path` value into a `Location` redirect header, and finally chain
the two together.

This is a genuine case of landing on the identical technique rather than a different one — same
vulnerable redirect, same internal target, same final payload shape. The only difference is delivery:
PortSwigger drives it by editing the `stockApi` value directly in Burp Repeater, we drove it by calling
`exploit_ssrf_open_redirect()` with the redirect endpoint and internal target as arguments. For a
single-shot chained request like this one, both approaches produce the exact same two HTTP requests on
the wire.

## What This Teaches Us

Restricting `stockApi` to relative paths looks, on its face, like a much stronger control than the
blacklist in the previous lab — there's no string to obfuscate, no encoding to sneak past. But the
restriction only ever inspected the parameter in isolation. It had no way to know that one of those
"safe" relative paths on the same trusted application would itself issue a redirect to anywhere the
caller wants. Any open redirect anywhere on an origin that an SSRF filter implicitly trusts collapses
that filter completely, because the filter's validation happens before the redirect, and the server's
actual fetch happens after it. The fix has to account for that: either the HTTP client making the
server-side request must refuse to follow redirects at all, or the destination has to be re-validated
against the allowlist after every redirect hop, not just on the URL the caller originally supplied.
