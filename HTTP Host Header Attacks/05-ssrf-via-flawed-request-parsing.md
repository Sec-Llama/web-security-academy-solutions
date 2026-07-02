# SSRF via flawed request parsing

**Category:** HTTP Host Header Attacks
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/host-header/exploiting/lab-host-header-ssrf-via-flawed-request-parsing

The previous lab in this series relied on a proxy that trusted the Host header outright. This one
is the harder version: the proxy actually validates the Host header and blocks tampering with it —
but validation and routing don't have to look at the same part of the request, and when they don't,
blocking one path doesn't close the other.

## The Target

A plain `GET /` with a modified Host header gets rejected outright here, unlike the previous lab.
That's the first sign this proxy is doing real validation rather than none at all — which makes it
worth asking exactly what it's validating, rather than assuming the Host header is unconditionally
safe.

## The Investigation

HTTP normally allows two forms in the request line: a relative path (`GET /path`) or a full absolute
URL (`GET https://domain/path`). Servers rarely see the absolute-URL form outside of proxy contexts,
but it's still legal HTTP/1.1. We tried it here specifically because a proxy that validates "the
Host" might mean the request-line target when an absolute URL is present, rather than the `Host`
header — those are two different values that are supposed to agree but don't have to.

Sending `GET https://LAB-DOMAIN/ HTTP/1.1` with an unmodified Host header worked normally, confirming
absolute-URL requests are accepted at all. The real test was combining that with a modified Host
header: `GET https://LAB-DOMAIN/ HTTP/1.1` plus `Host: 192.168.0.X`. Without the absolute URL, that
same Host tampering returned a flat 403. With it, we got a 504 Gateway Timeout instead — the request
was no longer being rejected, it was being *routed*, and routed to an address with nothing behind
it. That status-code swap, 403 to 504, was the confirmation: the proxy validates the request-line
target when an absolute URL is present, but still routes based on the Host header regardless of
which one it just checked.

Sending an absolute-URL request at all isn't something `httpx` supports — it normalizes the request
line and won't let you construct `GET https://host/path HTTP/1.1` with an independently-set Host
header. This lab needed the same raw-TLS-socket approach as the cache poisoning lab, for the same
underlying reason: the vulnerability lives in a part of the request that high-level HTTP clients
don't expose direct control over.

## The Exploit

With cookies collected from a normal homepage visit (the same requirement as the previous lab), we
scanned `192.168.0.0/24` concurrently over raw sockets, sending absolute-URL requests with the Host
header set to each candidate:

```
GET https://LAB-DOMAIN/ HTTP/1.1
Host: 192.168.0.X
Cookie: <session cookies>
```

Any response other than 504, a connection error, or 403 marked a live internal host. That IP turned
out to host the admin panel. Requesting it with the same absolute-URL structure:

```
GET https://LAB-DOMAIN/admin HTTP/1.1
Host: 192.168.0.X
Cookie: <session cookies>
```

returned the panel with a CSRF token, and a fresh session cookie in the response's `Set-Cookie`
header that we captured and reused. The delete request followed the same pattern:

```
POST https://LAB-DOMAIN/admin/delete HTTP/1.1
Host: 192.168.0.X
Cookie: <updated session cookies>
Body: csrf=<token>&username=carlos
```

which deleted `carlos` and solved the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the identical logic chain: confirm the home page loads with an
unmodified request, discover that supplying an absolute URL in the request line still works,
observe that Host-header tampering combined with the absolute URL produces a timeout instead of a
block, then use Burp Collaborator to confirm the middleware issues real outbound requests based on
this combination before sweeping `192.168.0.0/24` with Burp Intruder (again with "Update Host header
to match target" deselected) to find the admin IP.

The technique is the same start to finish — this lab and the previous one are close siblings, and
both required stepping outside what a standard HTTP client can send. The difference from the
official path is the same pairing seen throughout this series: Intruder's payload sweep against our
`ThreadPoolExecutor` scan, and Burp's native support for absolute-URL request lines against our raw
socket construction of the same bytes.

## What This Teaches Us

The lesson here is sharper than "the Host header isn't trustworthy" — it's that *which* part of a
request a security control validates matters as much as whether validation happens at all. This
proxy wasn't careless; it actively checked something. It just checked the request-line target while
routing on the Host header, and those two values are only guaranteed to match when nobody's trying
to make them diverge. Any system with more than one code path for extracting "the destination" from
an HTTP request needs every one of those paths to agree, or an attacker gets to pick which one gets
validated and which one gets acted on.
