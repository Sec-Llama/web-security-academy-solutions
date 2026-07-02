# Exploiting HTTP request smuggling to reveal front-end request rewriting

**Category:** HTTP Request Smuggling
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/request-smuggling/exploiting/lab-reveal-front-end-request-rewriting

Front-ends often rewrite requests before forwarding them — adding a client IP header for the back-end to trust, stripping headers the origin shouldn't see, injecting TLS metadata. None of that rewriting is visible to us as an outside attacker under normal circumstances. Request smuggling changes that: if we can get the back-end to reflect a request straight back at us, we get to read exactly what the front-end silently added.

## The Target

The admin panel here is restricted to requests originating from `127.0.0.1` — enforced by the back-end checking a header the front-end injects with the real client IP, since the back-end itself only ever sees the front-end's own connection. The application also has a search function that reflects the `search` parameter's value back into the response, which turns out to be the key that unlocks everything else.

## The Investigation

The reflected search parameter is what makes this lab solvable at all: if we can get the back-end to echo a request's raw headers back to us as if they were search terms, we can read whatever the front-end injected into that request on its way through. The approach was to smuggle a `POST /search` request with a large enough `Content-Length` that it doesn't complete on its own — instead, our real follow-up request's headers get appended onto the tail of the smuggled request's body, get rewritten by the front-end along the way, and then get reflected back by the search feature as part of its own response.

We captured a session cookie first via a normal request, then smuggled a `POST /search` request positioned so that whatever arrived after it (which the front-end would rewrite before forwarding) landed inside the `search=` parameter value:

```
POST /search HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 500

search=
```

Once the merged response reflected the rewritten request back at us, we searched it for a header matching the pattern `X-*-Ip` — the naming convention the front-end used for the injected client IP header. Finding that header name is the entire point of the lab: it's not documented anywhere, and the only way to learn it is to make the back-end tell us.

## The Exploit

The first smuggle captured the header name via reflection:

```
POST / HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 130
Transfer-Encoding: chunked

0

POST /search HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 500

search=
```

The reflected search results revealed a header of the form `X-abcdef-Ip: <front-end-assigned IP>` (the exact prefix is randomized per lab instance). With that header name in hand, we smuggled a second request straight at `/admin`, forging that exact header with the value `127.0.0.1`:

```
GET /admin HTTP/1.1
Host: TARGET
X-abcdef-Ip: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

This got us into the admin panel, from which we extracted the delete link for `carlos` and re-smuggled a third request against that path, still carrying the forged IP header, completing the deletion.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution uses the identical reflection trick to recover the header name:

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 124
Transfer-Encoding: chunked

0

POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 200
Connection: close

search=test
```

then reads the reflected `X-*-Ip` header name out of the "Search results for" text in the merged response, and forges it exactly as we did to reach `/admin` and, subsequently, the delete endpoint. This is a case where the technique is genuinely identical end to end — there's no alternate path here, because the header name is randomized per lab instance and the reflection trick is the only way to learn it. The only divergence is delivery: their solution issues each of the three requests by hand through Burp Repeater's "send twice" pattern and reads the header name visually out of the response; our script parsed it out with a regex against the merged response body and fed it straight into the next smuggled payload without a human in the loop.

## What This Teaches Us

This lab is a good demonstration of request smuggling as an information-disclosure primitive, not just an access-control bypass — the actual vulnerability being exploited here is that the back-end trusts a header it can't verify the origin of, and smuggling is simply the mechanism that lets us read that header's name in the first place so we can forge it convincingly. Any architecture where a front-end injects a trust signal (an IP header, a TLS-verification header, an internal auth token) into requests before forwarding them is only as strong as the assumption that an attacker can never see or replicate that header — an assumption request smuggling breaks directly.
