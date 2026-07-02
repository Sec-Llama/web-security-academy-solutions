# HTTP request smuggling, confirming a TE.CL vulnerability via differential responses

**Category:** HTTP Request Smuggling
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-te-cl-via-differential-responses

The differential-response technique from the CL.TE confirmation lab applies just as directly to TE.CL — the direction of the trust discrepancy flips, but the underlying proof strategy is identical: smuggle a request to a path that can't exist, and let the resulting 404 on someone else's response speak for itself. What changes here is entirely in the mechanics of building a valid TE.CL payload, which is less forgiving than CL.TE about exact byte counts.

## The Target

Same lab shape as the TE.CL basic lab — front-end trusts `Transfer-Encoding`, back-end trusts `Content-Length` — but now the objective is a clean confirmation signal rather than a bypass or exploit.

## The Investigation

Because the back-end here reads a fixed `Content-Length` regardless of chunk boundaries, our smuggled 404 probe had to be wrapped inside a chunk whose declared size is large enough to contain the whole prefix, while the outer `Content-Length` is set short enough to cut the back-end's read off right after the chunk-size line. We reused the same `CL = len(chunk_size_hex) + 2` rule from the basic TE.CL lab, and packaged the smuggled request as a complete standalone `GET /404check` request with its own headers so the back-end had everything it needed to parse it as a real request once our bytes were left in its buffer:

```
GET /404check HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

## The Exploit

We wrapped that prefix in a TE.CL payload and fired it immediately followed by a normal `GET / HTTP/1.1` on the same raw keep-alive connection, checking the second response for a `404`:

```
POST / HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

7c
GET /404check HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
0

```

The front-end, trusting `Transfer-Encoding`, reads and forwards the entire chunked body, terminator included. The back-end, trusting only `Content-Length: 4`, reads just the four bytes of the chunk-size line (`7c\r\n`) and stops — leaving the complete smuggled `GET /404check` request, plus the closing `0\r\n\r\n` of our outer chunk, sitting in its buffer as the start of the next request. Our follow-up `GET /` request merges onto the tail end of that leftover data, and the response we get back is a 404 for a path we never actually requested with our real connection — direct proof the back-end processed the smuggled request as genuine.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution is functionally the same technique, smuggling a complete `POST /404` request inside a chunk sized to overrun the back-end's short `Content-Length`:

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked

5e
POST /404 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0
```

Same mechanism, same four-byte `Content-Length` truncation trick, same "confirm via 404" outcome — the only real differences are which HTTP method the smuggled probe uses (`POST` vs our `GET`) and the target path name, neither of which changes what the payload proves. Their solution also calls out explicitly to leave "Update Content-Length" unchecked in Burp Repeater, which is the manual-tooling equivalent of the raw-socket requirement we already had baked into every payload in this series — a library that recalculates `Content-Length` for you defeats this class of attack before it starts, whether that library is Burp's request editor or Python's `httpx`.

## What This Teaches Us

Confirming TE.CL the same way we confirmed CL.TE reinforces a point that's easy to lose sight of when you're deep in chunk-size arithmetic: the *detection* strategy for both variants is the same idea — smuggle something that produces an unmistakable response on someone else's next request — even though the *payload construction* is meaningfully different between them. That separation between "how do I prove this bug exists" and "how do I build a valid payload for this specific variant" is worth keeping distinct, because it's the same differential-response pattern that will keep showing up through every exploitation lab in this series, just wrapped around increasingly consequential smuggled content.
