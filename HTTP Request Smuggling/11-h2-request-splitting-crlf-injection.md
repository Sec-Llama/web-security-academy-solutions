# HTTP/2 request splitting via CRLF injection

**Category:** HTTP Request Smuggling
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-request-splitting-via-crlf-injection

The previous CRLF-injection lab used a smuggled header to trigger a chunked-encoding desync indirectly. This lab skips the intermediate step entirely: instead of injecting a header that *causes* a length discrepancy, we inject the full text of a second, complete HTTP request directly into a header value, and let the front-end's own downgrade behavior stitch it into something the back-end treats as two real requests.

## The Target

Same downgrading front-end/back-end pair as the other HTTP/2 labs in this series, this time targeted purely at response queue poisoning to break into the admin panel and delete `carlos`.

## The Investigation

The key mechanical detail is what the front-end does when it rewrites an HTTP/2 request into HTTP/1.1 text: it appends `\r\n\r\n` to terminate the header block, regardless of what's already in the header value we supplied. If our smuggled header value already contains its own `\r\n\r\n` followed by a complete second request, the front-end's own termination sequence doesn't create a problem — it just closes out our (empty) trailing header, and the complete request we embedded earlier in the value is left standing as a fully independent HTTP/1.1 request once the downgrade is done.

We built this with the same disabled-validation `h2` configuration as the earlier CRLF labs, injecting the smuggled request directly into a custom header's value:

```
foo: bar\r\n\r\nGET /x HTTP/1.1\r\nHost: TARGET
```

Unlike the previous lab, this doesn't rely on triggering a secondary TE.CL-style desync — the CRLF sequence directly splits the request stream, so the technique reads more like classic HTTP/1.1 request splitting than a length-based smuggle, just delivered through an HTTP/2 header value instead of a URL or cookie. As with the response-queue-poisoning lab, we targeted a nonexistent path (`/x`) for both halves specifically so every normal response is a clean 404, making any other status code an unambiguous signal that we've captured a response meant for someone else.

## The Exploit

```
:method: GET
:path: /x
:authority: TARGET
foo: bar\r\n\r\nGET /x HTTP/1.1\r\nHost: TARGET

```

Each send of this payload serves two purposes at once: it re-poisons the response queue by injecting a second complete request the front-end never accounted for, and it simultaneously acts as a capture probe, since whatever comes back in response to sending it is either our own expected 404 or — if the queue is already poisoned from a previous send — some other user's response that got shifted into our slot. We resent the same payload roughly every five seconds and checked each response; on attempt 37 of a planned 60, the response that came back was a `302` redirect carrying the admin user's freshly-issued session cookie from a post-login flow, rather than our expected 404. We copied that cookie, issued `GET /admin` with it repeatedly until a clean `200` came back with the admin panel content, extracted the delete link for `carlos`, and hit it to solve the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution injects the identical CRLF split into a custom header value and targets the same nonexistent-path pattern for both requests:

```
foo
bar\r\n
\r\n
GET /x HTTP/1.1\r\n
Host: YOUR-LAB-ID.web-security-academy.net
```

then polls every ~5 seconds until an unexpected response surfaces, with the same fallback of sending ten ordinary requests to reset the connection if the attack stalls. This is functionally the same payload and the same polling strategy we used, arrived at through Burp's Inspector letting you type a header value containing literal `\r\n\r\n` sequences directly. The dual-purpose nature of each poisoning request — simultaneously re-poisoning the queue and checking whether it's already poisoned — is inherent to the technique itself, not a scripting optimization; both our approach and PortSwigger's rely on it, because there's no way to poison the queue without also consuming one of the responses it produces.

## What This Teaches Us

Request splitting via CRLF injection is arguably the most direct version of "HTTP/2's binary framing doesn't protect you from downgrading" — there's no intermediate desync condition to set up, just a raw injection of request-terminating bytes into a value the front-end trusts enough to pass through unmodified. It's also a useful reminder that response queue poisoning attacks are inherently probabilistic even once the underlying injection works reliably: attempt 37 out of a planned 60 succeeding is not a tooling limitation, it's the nature of racing against real connection-routing and timing behavior on a live server, and any automation built around this technique needs to budget for a real retry loop rather than a single clean shot.
