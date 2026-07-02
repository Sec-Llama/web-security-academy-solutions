# Blind SSRF with out-of-band detection

**Category:** Server-Side Request Forgery (SSRF)
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/ssrf/blind/lab-out-of-band-detection

Every lab so far returned the fetched resource straight back to us — we could read the admin page in
the response body and confirm the vulnerability visually. Blind SSRF removes that entirely: the server
makes the request, but nothing about what it fetched, or whether it succeeded, ever comes back in the
HTTP response. Proving the vulnerability exists means proving a request happened somewhere we can't
see, using infrastructure we don't fully control.

## The Target

This application has analytics software watching page views, and it fetches whatever URL sits in the
`Referer` header of an incoming request — presumably to log referring sites. A normal request looks
like:

```
GET /product?productId=1
Referer: https://normal-referring-site.com
```

There's no visible connection between this header and any server-side fetch — the response to this
request is just the product page, identical whether or not the analytics software actually reaches
out to the `Referer` URL.

## The Investigation

With nothing coming back in-band, the only way to confirm the fetch happens at all is to control a
domain we can observe requests hitting, and see whether one arrives after setting `Referer` to that
domain. PortSwigger Academy labs restrict outbound network egress specifically to prevent working
around this with a self-hosted or third-party out-of-band listener — but the labs whitelist one very
specific exception: `*.oastify.com`, PortSwigger's own OAST domain, is reachable from inside the lab
environment because the lab platform itself watches for interactions against it.

That mattered here for a reason distinct from Burp Collaborator's usual role. In earlier out-of-band
work in this series, the point of Collaborator was reading the resulting DNS/HTTP interaction log to
recover exfiltrated data — something only Burp Suite Professional's licensed client can do. This lab
doesn't need us to read anything back at all. The lab's own solve condition isn't "we observed a
callback" — it's "the *lab platform itself* observed a callback to its own domain." That means a
random, unguessable subdomain of `oastify.com`, generated locally with no Burp Collaborator client
involved, is enough: we just need the interaction to happen, and PortSwigger's own infrastructure
handles detecting it and flipping the lab to solved.

## The Exploit

`lab_blind_oob()` generates a fresh random token, builds an `oastify.com` URL from it, and sets that
as the `Referer` header on a handful of product page requests:

```python
token = secrets.token_hex(16)
oast = f"http://{token}.oastify.com"
result = exploit_ssrf_blind_oob(base_url, oast, "Referer", [1, 2, 3], client)
```

`exploit_ssrf_blind_oob()` issues the actual requests:

```python
for pid in product_ids:
    r = client.get(f"{url}/product?productId={pid}", headers={header_name: oast_url})
```

With `Referer: http://<random-token>.oastify.com` set on requests for product IDs 1, 2, and 3, the
analytics software fetched that URL server-side to log the "referrer" — an outbound HTTP (and DNS)
interaction to our unique subdomain, exactly the signal the lab platform is watching for. Our
capability notes recorded this resolving in about a second once the Referer-triggered fetch actually
fired, and polling the lab's own solved-state check (`"congratulations"` in the response for `/`)
confirmed it.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution uses Burp Collaborator directly: intercept the product request in Repeater,
right-click the `Referer` header and choose "Insert Collaborator Payload" to swap in a Collaborator-
generated subdomain, send the request, then switch to the Collaborator tab and click "Poll now" to
read back the resulting DNS and HTTP interactions.

We didn't use Collaborator at all, and this is a genuine technique divergence, not just a tooling one.
The underlying trigger is identical either way — a server-side fetch of an attacker-controlled
`Referer` URL — but the two approaches prove it differently. PortSwigger's path proves the SSRF by
directly reading the resulting interaction in Collaborator's own log, which is the rigorous way to do
it and the only way that would hold up as real evidence outside a training lab. Our path proves it
indirectly: we rely on the lab platform's own detection of that same interaction against its
whitelisted `oastify.com` domain, which is sufficient to flip this specific lab's solved flag but isn't
a general substitute for actually reading an out-of-band interaction log. It was enough here because
the lab's solve condition and our OAST domain happened to be the same infrastructure PortSwigger
already watches — a shortcut this particular lab happens to allow, not a general way around needing
Collaborator for out-of-band work.

## What This Teaches Us

Blind SSRF is a reminder that "the response doesn't show anything" is not the same as "nothing
happened." The analytics software's fetch was completely invisible from the HTTP response, but it
still executed a real outbound request carrying attacker-supplied data as its destination — which
means anywhere that fetch could be pointed, from internal admin panels to cloud metadata endpoints, was
exploitable with zero in-band feedback the whole way through. The defense burden here doesn't change
just because the response is quiet: the same input validation that stops in-band SSRF has to apply to
every header a server-side fetch might key off of, `Referer` included, and "we don't return the
response" is not a mitigation on its own — it just makes the vulnerability harder to detect, not
harder to exploit.
