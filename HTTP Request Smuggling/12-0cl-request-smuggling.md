# 0.CL request smuggling

**Category:** HTTP Request Smuggling
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-0cl-request-smuggling

This lab is built on research published in 2025 — James Kettle's "HTTP/1.1 Must Die" — and it's the newest, hardest technique in this whole series. Where every earlier lab exploited a straightforward disagreement over which length header to trust, 0.CL exploits something subtler: a front-end that treats a malformed `Content-Length` as if it isn't there at all, while the back-end honors it anyway. Solving it took building an entirely new execution path outside our normal Python toolchain, because the attack turned out to be one that Python itself can't reliably deliver.

## The Target

The lab tells you almost nothing up front beyond "this lab is vulnerable to 0.CL request smuggling" and that a simulated user visits the homepage every five seconds — the goal is firing `alert()` in that visitor's browser. There's no admin panel or delete-user flow to reverse-engineer here; the entire challenge is landing the desync reliably enough to poison a response queue with an XSS payload before the victim's next page load.

## The Investigation

0.CL is a parser-discrepancy attack rather than a classic CL.TE/TE.CL mismatch. The relevant discrepancy is Hidden-Visible (H-V): if we send a `Content-Length` header mutated just enough that the front-end's parser doesn't recognize it as a valid length header at all — a space inserted before the colon, `Content-Length : 45` — the front-end treats the request as having no body, while a more lenient back-end parser still reads the header value and consumes that many bytes as body content. The front-end thinks it sent a zero-body request; the back-end is sitting there waiting for 45 more bytes that the front-end never accounted for.

That mismatch alone creates a deadlock, not an exploit — the back-end just hangs waiting for bytes that aren't coming, unless something on the response side breaks the standoff. That's what an Early-Response Gadget (ERG) is for: an endpoint that responds *before* fully reading the request body, such as a static asset that gets served regardless of a POST body attached to it. Using `/resources/css/labsBlog.css` as the ERG, we built a three-stage pipeline over one connection: stage 1 is the POST to the ERG carrying the hidden, space-mutated `Content-Length`; stage 2 is a second request (`OPTIONS /`, since the server rejects a bodied `GET`) that the *front-end* treats as a separate, second request but the *back-end* consumes as the hidden bytes of stage 1's body; stage 3 is whatever's left over after the back-end finishes reading stage 2 as body — a genuinely new request the back-end parses on its own, prefixed with our chosen headers.

Getting there required ruling out several approaches first. Detection — confirming the 302-plus-404 signature that proves the discrepancy exists — worked fine in pure Python over raw sockets. Exploitation did not. The three-stage pipeline depends on all three stages landing on the *same* back-end TCP connection in the *same* order, and Python's socket writes get buffered and potentially recombined or split unpredictably by the OS network stack before they ever reach the wire as distinct segments. We could confirm the desync existed, but couldn't reliably win the race needed to poison a real response queue with it — the operating system's own TCP buffering was actively working against the timing this attack depends on.

The fix was to stop fighting Python's socket layer and write a small Go program instead. A single `conn.Write()` call concatenating all three stages guarantees they leave as one contiguous write and land on one back-end connection, eliminating the probabilistic collision entirely — no amount of careful timing in Python could match that guarantee, because the problem wasn't our logic, it was the runtime's I/O buffering underneath it.

## The Exploit

The winning configuration, run through the Go pipeline solver:

```
stage1 = "POST /resources/css/labsBlog.css HTTP/1.1\r\nHost: TARGET\r\n
           Content-Type: application/x-www-form-urlencoded\r\nConnection: keep-alive\r\n
           Content-Length : 45\r\n\r\n"

stage2Full = "OPTIONS / HTTP/1.1\r\nContent-Length: 210\r\nX: Y"
           + "GET /hopefully404 HTTP/1.1\r\nHost: TARGET\r\n...keep-alive\r\n\r\n"
           + "GET /post?postId=1 HTTP/1.1\r\nHost: TARGET\r\n
              User-Agent: a\"/><script>alert(1)</script>\r\n
              Content-Length: 5\r\n\r\nx=1"

conn.Write([]byte(stage1 + stage2Full))
```

The hidden `Content-Length : 45` matches the exact byte length of the `OPTIONS /` stage2 prefix, which the back-end silently consumes as stage1's body. What's left over — the smuggled `GET /post?postId=1` request carrying an XSS payload in its `User-Agent` header — becomes a complete, independent request the back-end parses on its own, poisoning the response queue with an `alert(1)` payload sitting in the response the next real visitor is due to receive. With TLS session caching and HTTP/1.1 ALPN negotiation configured to make reconnection fast, and the ERG/ port/host parameters swept automatically, the lab solved in 99.5 seconds.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger has not published a written step-by-step solution for this lab at the time of writing. The "Solution" section on the lab page is a recorded livestream with researcher James Kettle rather than a text walkthrough, which is a reasonable choice given 0.CL is presented explicitly as a real-world technique from very recent published research rather than a settled, long-documented pattern like CL.TE. We can't compare our approach against a specific PortSwigger-authored payload here, but the general technique — hidden `Content-Length` mutation, an ERG to break the response deadlock, and a multi-stage pipeline to convert the discrepancy into a full desync — is exactly what the "HTTP/1.1 Must Die" research the lab cites describes, and it's what our own capability document independently arrived at through the detection-then-exploitation process above.

## What This Teaches Us

The most transferable lesson from this lab has nothing to do with `Content-Length` parsing — it's that "the technique doesn't work" and "my tool can't deliver the technique" are different findings, and conflating them costs real time. Python's detection code proved the 0.CL discrepancy was real; it just couldn't win the timing race needed to weaponize it, because the constraint lived in the OS socket layer, not in our understanding of the attack. Once we built a purpose-specific Go client that guarantees single-write, single-connection delivery, the same logic that failed probabilistically in Python solved reliably in under two minutes. On the vulnerability side, 0.CL is the sharpest version yet of a theme running through this entire series: as long as two independent HTTP parsers can be fed the same bytes and reach different conclusions about where a request ends, there will be a new variant to find — and this one is recent enough that some production infrastructure almost certainly hasn't been tested against it yet.
