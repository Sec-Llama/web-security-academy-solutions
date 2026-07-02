# Basic SSRF against the local server

**Category:** Server-Side Request Forgery (SSRF)
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost

Server-side request forgery turns the application itself into a proxy the attacker controls. Capital
One's 2019 breach — over 100 million customer records — started with exactly this shape of bug: a
misconfigured server tricked into requesting the AWS metadata endpoint on the attacker's behalf. This
first lab strips SSRF down to its purest form: no filters, no blind exfiltration, just a server that
will fetch whatever URL you hand it and show you the result.

## The Target

The application is a storefront with a stock-checking feature. Viewing a product and clicking "Check
stock" fires a request that the front end never actually needs to see the internals of — it just
needs a stock count back:

```
POST /product/stock
stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1
```

The `stockApi` parameter is a full URL, fetched server-side, with the response relayed back to the
browser. There's also an `/admin` path on this same application that returns "Forbidden" when we hit
it directly from our browser — access to it is restricted by network position, not by any credential
check.

## The Investigation

An access control that's enforced by network position rather than authentication is precisely what
SSRF defeats: if the server itself can reach `/admin` because it's making the request from inside the
trusted network, then getting the server to make that request on our behalf bypasses the restriction
entirely. Our detector (`detect_ssrf()` in `SSRF.py`) tests exactly this — it substitutes a loopback
URL into the target parameter and checks whether the response comes back as a large, successful page
rather than an error, which is the signature of an unfiltered fetch:

```python
r = client.request(method, url, data={param_name: test_url})
if r.status_code == 200 and len(r.text) > 100:
    ctx.vulnerable = True
    ctx.filter_type = "none"
```

Pointing `stockApi` at `http://localhost/admin` came back exactly that way — a full 200 response
containing the admin interface HTML, something the same request from our browser could never reach
directly. No blacklist, no whitelist, nothing standing between the parameter and an arbitrary fetch.

## The Exploit

With the admin page in hand, the next step was finding the action we actually wanted: deleting the
user `carlos`. The `lab_basic_localhost()` wrapper fetches the admin page via SSRF, then regexes the
returned HTML for the delete link rather than reading it by eye:

```python
delete_match = re.search(r'href="(/admin/delete\?username=carlos)"', result.data)
```

That surfaced `/admin/delete?username=carlos`, which we fed back through the same `stockApi`
parameter to trigger the delete action server-side:

```
stockApi=http://localhost/admin
stockApi=http://localhost/admin/delete?username=carlos
```

The second request returned successfully, and the lab's solved check — polling `/` for the string
"congratulations" — confirmed it.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's published solution reaches the same two requests, in the same order: set `stockApi` to
`http://localhost/admin` to read the interface, read the HTML to find
`http://localhost/admin/delete?username=carlos`, then submit that as the second `stockApi` value.
This matches our approach exactly — same target URLs, same two-step sequence.

The only real difference is delivery and how the delete link gets read. PortSwigger's walkthrough is
manual: intercept the stock-check request in Burp Repeater, edit `stockApi` by hand, and read the
returned admin HTML with your own eyes to spot the delete link. We drove the same two requests
through a Python script, and used a regex against the response body to extract the delete link
automatically rather than reading it visually. For a two-request lab like this one, both paths
converge on identical wire traffic — the difference is purely in who (or what) parses the HTML.

## What This Teaches Us

The vulnerability here isn't really in the `stockApi` parameter — it's in treating "can only be
reached from inside the network" as equivalent to "is secure." The `/admin` endpoint had no
authentication of its own; its entire protection model assumed that only the trusted server would
ever be in a position to request it. SSRF collapses that assumption by turning the trusted server
into an attacker-controlled proxy. It's the same root cause behind the Capital One breach at a much
larger scale: a server with legitimate access to sensitive internal resources, and a request path an
attacker could redirect. The fix is the same at any scale — validate the destination host against an
allowlist before the server ever dials out, rather than trusting that only "the server" would ever be
the one making the request.
