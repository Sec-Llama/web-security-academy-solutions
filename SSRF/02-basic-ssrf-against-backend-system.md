# Basic SSRF against another back-end system

**Category:** Server-Side Request Forgery (SSRF)
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-backend-system

The previous lab proved the application would fetch whatever URL we handed it. This one asks a
harder question: what if the interesting target isn't `localhost` at all, but some other machine on
the same internal network that we can't name because we've never seen its address? The server's
network position doesn't just expose itself — it exposes everything it can route to.

## The Target

Same stock-check feature, same `stockApi` parameter taking a full URL server-side:

```
POST /product/stock
stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1
```

This time, though, there's no local `/admin` path to fall back on — the admin interface for this lab
lives on a separate back-end host somewhere in the `192.168.0.0/24` private range, on port 8080. We
don't know which address it's actually listening on.

## The Investigation

Not knowing the exact internal IP just turns this into a sweep instead of a single request. Our
`scan_internal_range()` function fires the `stockApi` parameter at every address in a range
concurrently and looks for a response that's both a `200` and large enough to be a real page rather
than an empty or error response:

```python
def check_ip(i: int) -> Optional[Tuple[str, int, int]]:
    target = f"{ip_prefix}{i}:{port}{path}"
    r = client.request(method, url, data={param_name: target})
    if r.status_code == 200 and len(r.text) > 200:
        return (target, r.status_code, len(r.text))
```

Run against `http://192.168.0.1-255:8080/admin` with 20 concurrent workers, one address in that range
came back with a full `200` admin page while the rest timed out or errored — the same signal our
detector used in the previous lab, just applied across 255 candidates instead of one.

Reading the returned HTML for the delete link surfaced a detail the first lab didn't have: the href
wasn't a clean relative path. It came back as an absolute-looking internal URL embedded inside the
`href` attribute — `/http://192.168.0.X:8080/admin/delete?username=carlos` — because the back-end
application constructs its own links using the full internal host it knows about, not a path relative
to whatever fetched it. A regex anchored to a plain `/admin/delete?username=carlos` path would have
missed this entirely, so we widened it to match the delete path anywhere inside the href:

```python
delete_match = re.search(r'href="[^"]*(/admin/delete\?username=carlos)"', result.data)
```

## The Exploit

With the internal admin host identified and the delete path extracted, we rebuilt the full internal
URL by pulling the discovered IP and port back out of the original hit and appending the delete path:

```python
ip_match = re.search(r'(http://192\.168\.0\.\d+:\d+)', target_url)
internal_base = ip_match.group(1) if ip_match else target_url.rsplit("/", 1)[0]
delete_url = f"{internal_base}{delete_match.group(1)}"
```

That produced a request shape identical to Lab 1's, just pointed at the discovered internal host
instead of `localhost`:

```
stockApi=http://192.168.0.X:8080/admin
stockApi=http://192.168.0.X:8080/admin/delete?username=carlos
```

The delete request came back and the lab's solved check confirmed carlos was gone.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution sweeps the same `192.168.0.0/24` range on port 8080, but does it through Burp
Intruder: set `stockApi` to `http://192.168.0.1:8080/admin`, mark the final IP octet as the payload
position, run a Numbers payload from 1 to 255, then sort the attack results by status code to spot
the single `200`. That's the same sweep-and-filter logic our `scan_internal_range()` function runs,
just executed as a batch Intruder attack instead of a `ThreadPoolExecutor` with 20 concurrent workers.

The official write-up's final step is simpler than what we had to handle: it just says to change the
path in `stockApi` to `/admin/delete?username=carlos` once the admin host is already selected in
Repeater. Our script hit a wrinkle that a human skimming the rendered admin page in Burp's browser
view wouldn't necessarily notice or need to handle explicitly — the delete link's `href` attribute is
itself an absolute internal URL rather than a clean relative path, which meant our regex had to be
loosened to find the delete path wherever it appeared in the href rather than assuming it started the
string. Functionally this doesn't change the exploit at all, but it's a good example of how automating
HTML parsing surfaces small formatting quirks that manual inspection glosses right over.

## What This Teaches Us

This lab is the same vulnerability as the first one, but it demonstrates the more dangerous version of
it: SSRF doesn't just expose paths on the vulnerable server itself, it exposes the server's entire
reachable network. An admin interface on an internal host with no authentication of its own is
"secure" only as long as nothing with network access to it can be redirected by an outside attacker.
Once the front-end application became a proxy we could point anywhere in `192.168.0.0/24`, that
internal host's total absence of auth became directly exploitable from outside the network entirely.
The fix is the same allowlist principle as Lab 1, just harder to get right in practice: every internal
host a server-side fetch could conceivably reach needs to be explicitly excluded, not just the ones an
engineer happened to think of.
