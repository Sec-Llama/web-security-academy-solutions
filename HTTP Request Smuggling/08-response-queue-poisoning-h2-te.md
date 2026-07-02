# Response queue poisoning via H2.TE request smuggling

**Category:** HTTP Request Smuggling
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/request-smuggling/advanced/response-queue-poisoning/lab-request-smuggling-h2-response-queue-poisoning-via-te-request-smuggling

Response queue poisoning is the most consequential outcome request smuggling can produce over a reused connection: instead of a single smuggled request affecting a single follow-up, the back-end's own response ordering gets permanently out of sync with the front-end's expectations, and *every* subsequent request on that connection receives someone else's response until the connection is torn down. This lab builds that condition over an HTTP/2 front-end that downgrades to HTTP/1.1 for the back-end, using `Transfer-Encoding` injected directly as an HTTP/2 header.

## The Target

The lab supports HTTP/2 to the front-end, which then rewrites requests to HTTP/1.1 before forwarding them to the back-end. Because HTTP/2 uses binary framing to express message length — not a `Content-Length` or `Transfer-Encoding` header — a `transfer-encoding` header injected into an HTTP/2 request is metadata the HTTP/2 layer itself ignores, but which becomes a real, meaningful header the moment the front-end downgrades the request to HTTP/1.1 text for the back-end.

## The Investigation

We used the Python `h2` library to speak raw HTTP/2 frames rather than trying to coerce a higher-level HTTP/2 client into sending a header combination it would normally reject as invalid — the `h2` library will happily send `transfer-encoding: chunked` as an HTTP/2 header field if told to, since HTTP/2 itself has no length semantics tied to that name. Once the front-end downgrades our request to HTTP/1.1, that header becomes real, and the back-end starts parsing the body as chunked while the front-end continues to track the request by its HTTP/2 frame length — creating exactly the same desync condition as classic TE.CL, just originating from an HTTP/2 connection.

The response queue poisoning part requires smuggling a *complete* standalone request rather than a partial prefix, so that the back-end genuinely generates a second, distinct response the front-end never expects. We targeted a nonexistent path (`/x`) for both the smuggling request and the smuggled request deliberately — every normal response on that path is a 404, so any response that comes back *not* a 404 is immediate, unambiguous proof we've captured someone else's response out of the queue.

## The Exploit

```
:method: POST
:path: /x
:authority: TARGET
content-type: application/x-www-form-urlencoded
transfer-encoding: chunked

0

GET /x HTTP/1.1
Host: TARGET

```

Sending this repeatedly poisons the response queue: the back-end sees two requests where the front-end only sent one, generates two responses, and the front-end's response-matching falls one position out of sync from that point forward. We sent the same poisoning request again roughly every five seconds and checked the response each time — most attempts simply return our own expected 404, but a poisoned queue means that occasionally the response belongs to a different request entirely. After enough attempts, one comes back as a `302` redirect containing the admin user's freshly-issued session cookie from their post-login flow. We copied that cookie and issued `GET /admin` with it repeatedly until a clean `200` with the admin panel came back — accessing the admin panel through response queue poisoning sometimes surfaces intermediate wrong responses while the queue is still settling, so persistence mattered here — then extracted the delete link for `carlos` from the panel and hit it to complete the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution builds up the same attack in the same order: first confirm a basic H2.TE desync with an arbitrary smuggled prefix over HTTP/2, then switch to smuggling a complete request to `/x` for both the poisoning and the capture probe, and finally poll the response every ~5 seconds until an unexpected status code — the admin's `302` — surfaces:

```
POST /x HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Transfer-Encoding: chunked

0

GET /x HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```

This is the same mechanism and the same non-existent-path trick we used, expressed through Burp Repeater's HTTP/2 protocol switch rather than the `h2` library. Their solution notes the identical recovery step if the attack stalls — "send 10 ordinary requests to reset the connection and try again" — which matches a real failure mode we hit as well. The delivery difference is more pronounced here than in the HTTP/1.1 labs: Burp Repeater has a dedicated protocol toggle to switch a request to HTTP/2 with a click, while our approach required building raw HTTP/2 frames through the `h2` library with header validation and normalization explicitly disabled — by default, that library silently sanitizes header values in ways that would have neutered this exact attack, a lesson that became a standing requirement for every HTTP/2 payload in this series after we ran into it.

## What This Teaches Us

Response queue poisoning is the escalation that turns "I can smuggle one request" into "I can read an unbounded stream of other people's responses," and it's a good demonstration of why connection reuse — normally a performance optimization — becomes a liability the moment request boundaries can be manipulated. It's also a clean illustration that HTTP/2 downgrading doesn't introduce a new vulnerability class so much as it opens a new delivery mechanism for the same TE.CL-style discrepancy: the header that causes the desync is identical to HTTP/1.1 TE.CL, it's just injected through a protocol that was never designed to carry it as meaningful text in the first place.
