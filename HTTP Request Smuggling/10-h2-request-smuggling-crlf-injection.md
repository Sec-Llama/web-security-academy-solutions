# HTTP/2 request smuggling via CRLF injection

**Category:** HTTP Request Smuggling
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-request-smuggling-via-crlf-injection

HTTP/2's binary framing is supposed to make request smuggling structurally impossible — there's no ambiguous text-based length header to disagree about, because the frame itself carries an authoritative length. That guarantee only holds as long as the HTTP/2 layer stays binary all the way through. The moment a front-end downgrades a request to HTTP/1.1 text before forwarding it, any raw `\r\n` sequence we managed to smuggle inside a header *value* turns into a literal line break the back-end's HTTP/1.1 parser will happily treat as a real header delimiter.

## The Target

The lab's blog post pages accept comments through `POST /post/comment` — an endpoint that, like the CL.TE-based capture lab earlier in this series, will echo back whatever body content it's handed if that body is malformed or incomplete. That's the same capture primitive from the CL.TE lab, reachable here through an HTTP/2 downgrade instead of a text-based Content-Length mismatch.

## The Investigation

HTTP/2 header values are allowed to contain raw carriage-return and line-feed bytes, because HPACK encodes them as opaque byte strings with no special meaning attached to any particular byte value — the restriction against `\r\n` in header values is an HTTP/1.1 parsing rule, not something HTTP/2 itself enforces. If we inject `\r\n` into an HTTP/2 header value and the front-end doesn't sanitize it before rewriting the request as HTTP/1.1 text, those bytes become a real header boundary that didn't exist in the original semantic request.

Getting the `h2` library to actually send raw CRLF bytes inside a header value took the same fix as the H2.CL lab: its default behavior silently strips or rejects `\r\n` sequences during header normalization, which defeats this attack before a single packet leaves the socket. With `validate_outbound_headers=False` and `normalize_outbound_headers=False` set explicitly, the library stops sanitizing outbound header values and sends exactly the bytes we specify — a configuration detail simple enough to miss entirely and conclude the technique doesn't work at all if you don't already know to look for it.

With that fixed, we injected a `Transfer-Encoding: chunked` header via CRLF hidden inside an otherwise-innocuous custom header's value:

```
foo: bar\r\nTransfer-Encoding: chunked
```

After downgrade, the front-end's rewritten HTTP/1.1 request contains two real headers where we sent one HTTP/2 header — `foo: bar` and, on its own line, `Transfer-Encoding: chunked` — reproducing the same H2.TE desync condition from the response-queue-poisoning lab, but reached through header-value injection instead of a direct `transfer-encoding` header.

## The Exploit

We confirmed the primitive first by smuggling an arbitrary prefix, then built the real capture payload targeting the comment endpoint. The DATA frame carries `0\r\n\r\n` (satisfying the fake chunked body we just declared) immediately followed by a complete second request — a `POST /post/comment` riding on our own session and CSRF token, with a `Content-Length` deliberately larger than the body we actually send:

```
:method: POST
:path: /
:authority: TARGET
content-type: application/x-www-form-urlencoded
foo: bar\r\nTransfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 1200
Cookie: session=ATTACKER_SESSION

csrf=CSRF_TOKEN&postId=2&name=test&email=test@test.net&website=https://test.net&comment=
```

Because `Content-Length: 1200` promises far more body than the `comment=` field we actually supplied, the back-end keeps that stream open waiting for the remaining bytes — and the next real visitor's request on the same connection gets appended straight onto our unterminated `comment` parameter. We sent this, waited roughly ten seconds for a real visitor to land on the poisoned connection, then read the post's comment thread: the captured text included the front slice of another request, headers and a session cookie among them. Extracting that cookie and loading `/my-account` with it authenticated us as the victim, which is the lab's solve condition.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution uses the identical CRLF-in-header-value injection to reach the same `Transfer-Encoding: chunked` smuggle:

```
foo
bar\r\n
Transfer-Encoding: chunked
```

but aims the captured-request technique at a different feature entirely — their smuggled request is a `POST /` appended to the site's `search=` parameter, exploiting the fact that recent searches get stored and displayed back to the same session. Refreshing the page immediately afterward is enough to capture the next visitor's request inside that search history, with the same "wait roughly 15 seconds, refreshing too early captures your own request instead" timing note we ran into ourselves, just against the comment thread instead of search history.

The CRLF-injection primitive itself is identical in both approaches — same header, same HPACK behavior, same H2.TE desync once the front-end downgrades to HTTP/1.1. Where we diverge is the capture surface: PortSwigger's walkthrough reuses the search feature (and drives the whole thing through Burp's Inspector panel, which accepts a literal `\r\n` typed into a header value and sends it as-is over HTTP/2); we reused the `/post/comment` capture primitive from this series' earlier CL.TE lab, since it was already a proven, working capture point and meant one less new mechanism to validate. Both land on the same underlying fact — an HTTP/2 connection can be made to hold a request open indefinitely, and whatever request follows on that connection gets swallowed into it — just surfaced through different storage.

## What This Teaches Us

This lab is a clean demonstration that "binary protocol" and "immune to text-injection bugs" aren't the same guarantee — HTTP/2 removes the *parsing* ambiguity that CL.TE and TE.CL exploit, but it doesn't remove the *downstream* text reinterpretation risk the moment a gateway rewrites frames back into HTTP/1.1 for a legacy back-end. Any front-end that performs this downgrade has to treat every byte in every header value as potentially hostile text, not just validate it against HTTP/2's own (much looser) framing rules — because HTTP/2 was never designed to prevent CRLF injection, it just moved where the injection has to be caught.
