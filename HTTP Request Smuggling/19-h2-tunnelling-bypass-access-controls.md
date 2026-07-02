# Bypassing access controls via HTTP/2 request tunnelling

**Category:** HTTP Request Smuggling
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/request-smuggling/advanced/request-tunnelling/lab-request-smuggling-h2-bypass-access-controls-via-request-tunnelling

Request tunnelling is what request smuggling looks like when connection reuse isn't available to exploit — instead of poisoning a shared back-end connection across multiple front-end requests, we hide an entire second request inside a *single* HTTP/2 request-response pair, so that one HTTP/2 stream produces two nested HTTP/1.1 exchanges after downgrade. This lab needed it specifically: the front-end here doesn't reuse connections to the back-end at all, closing off every classic smuggling technique we'd used up to this point.

## The Target

The front-end appends a set of client-authentication headers to every request before forwarding it to the back-end — presumably something like TLS client-certificate metadata, since the back-end's `/admin` panel trusts these headers to decide who's an authenticated administrator. Because the front-end doesn't reuse connections, we can't smuggle a request onto a connection a victim will later share; we have to get the *entire* attack to complete inside one request-response round trip.

## The Investigation

This lab uses CRLF injection in a header *name* rather than a header value — a distinct vector from the CRLF-in-value technique used in the earlier splitting and capture labs. Front-ends that sanitize header values for injected control characters don't necessarily apply the same sanitization to header names, since a header name isn't expected to need that scrutiny under normal circumstances. Confirming this took a small header-name probe:

```
Name:  foo: bar\r\n
       Host: abc
Value: xyz
```

An error response indicating the server had processed our injected `Host: abc` confirmed the front-end doesn't sanitize CRLF sequences hidden inside header names during downgrade.

The actual leak worked by abusing the site's search feature, which reflects the `search` parameter back into the response. We converted a normal search `GET` into a `POST` (the parameter still works in the body), then injected a large `Content-Length` and an extra `search=x` parameter through a CRLF-laden header name, followed by enough padding characters in the main body to push the request past that smuggled `Content-Length` boundary. Once the request exceeded the length we'd declared, the response reflected back not just our search term but the raw headers the front-end had appended after our injection point — including `X-SSL-VERIFIED`, `X-SSL-CLIENT-CN`, and a `X-FRONTEND-KEY` value unique to this lab instance. That's the whole vulnerability in one step: a reflection feature turned into a side-channel for reading headers we were never supposed to see, using request tunnelling to get the back-end to echo its own inbound headers back to us before the front-end's real ones arrived.

With those three header values in hand, forging admin access became a second CRLF-in-header-name injection — this time terminating the smuggled headers early with `\r\n\r\n` so the back-end never sees the front-end's *real* authentication headers appended afterward, only our forged ones:

```
Name:  foo: bar\r\n
       X-SSL-VERIFIED: 1\r\n
       X-SSL-CLIENT-CN: administrator\r\n
       X-FRONTEND-KEY: KEY\r\n
       \r\n
Value: xyz
```

## The Exploit

The header-leak request, as an HTTP/2 header with a CRLF-injected name:

```
name:  foo: bar\r\nContent-Length: 105\r\n\r\nsearch=
value: x
```

sent as a `POST /` with `Content-Type: application/x-www-form-urlencoded` and body padded past the smuggled `Content-Length`. The reflected response revealed the `X-FRONTEND-KEY` value alongside the other two headers. We then sent the forged-authentication request directly at `/admin`:

```
name:  foo: bar\r\nX-SSL-VERIFIED: 1\r\nX-SSL-CLIENT-CN: administrator\r\nX-FRONTEND-KEY: KEY\r\n\r\n
value: x
```

which returned a clean `200` with the full admin panel — proving the forged headers alone were sufficient once the real ones appended by the front-end landed after our early `\r\n\r\n` terminator and were simply never seen by the back-end. From the panel response we extracted the delete link for `carlos` and repeated the same forged-header tunnel against that path to complete the deletion.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the identical two-phase structure — leak the client-authentication headers via a CRLF-injected header name padding past a smuggled `Content-Length` on the search endpoint, then forge those exact headers with an early `\r\n\r\n` termination to reach `/admin`:

```
foo: bar\r\n
Content-Length: 500\r\n
\r\n
search=x
```
and, for the bypass itself:
```
foo: bar\r\n
\r\n
GET /admin HTTP/1.1\r\n
X-SSL-VERIFIED: 1\r\n
X-SSL-CLIENT-CN: administrator\r\n
X-FRONTEND-KEY: YOUR-UNIQUE-KEY\r\n
\r\n
```

This is the same technique in every meaningful respect — same header-name CRLF vector, same reflection leak, same early-termination forgery. The solution notes an extra practical step worth calling out: because tunnelling here means the *entire* attack happens inside a single request rather than across a poisoned connection, they explicitly use a `HEAD` request for the final step and adjust the target endpoint (`/login` instead of the full admin page) to keep the tunnelled response short enough to actually read back within the outer response's declared `Content-Length` — a constraint our approach handled by targeting endpoints with naturally short responses rather than needing a HEAD-specific workaround, since our forged-header approach terminates the back-end's view of the request early enough that this length mismatch didn't come up in the same way.

## What This Teaches Us

Request tunnelling exists because connection reuse isn't a prerequisite for this entire bug class — it's just the easiest delivery mechanism when it's available. A front-end that correctly avoids reusing back-end connections across different clients has closed off classic smuggling, but that's not the same as closing off every consequence of a CRLF-sanitization gap; the same downgrade-time text reinterpretation that powers connection-reuse attacks powers a single-request tunnel just as effectively. And the header-name-versus-header-value distinction here is a genuinely separate thing to test for in the wild — a front-end diligent about sanitizing values can still be blind to the same injection sitting in a name, simply because nobody expected a header name to need that scrutiny.
