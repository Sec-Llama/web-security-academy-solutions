# HTTP request smuggling, basic TE.CL vulnerability

**Category:** HTTP Request Smuggling
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl

CL.TE and TE.CL are mirror images of the same underlying bug, but they're not interchangeable in practice — a server pair that's safe against one can still be vulnerable to the other, because the vulnerability lives in *which* header each side trusts, not in the existence of the headers themselves. This lab is the TE.CL half of the pair: now it's the front-end that honors `Transfer-Encoding`, and the back-end that falls back to `Content-Length`.

## The Target

Same shape of application as the CL.TE lab — a front-end/back-end pair, with the front-end rejecting anything that isn't `GET` or `POST`. The difference is entirely in which server trusts which length header, which flips the direction the smuggled bytes travel and how the payload has to be constructed.

## The Investigation

Here the front-end parses the body as chunked and forwards every chunk, including the terminating `0\r\n\r\n`. The back-end ignores `Transfer-Encoding` and reads exactly `Content-Length` bytes. If we set `Content-Length` short enough, the back-end stops reading partway through our first chunk, and everything after that — including the rest of that chunk and any following chunks — gets left on the connection as the prefix of the next request.

Getting the `Content-Length` value right here needed more care than CL.TE did. The back-end reads `Content-Length` bytes starting from the body; if we set it to cover just the chunk-size line, the back-end stops right after consuming the hex chunk-size token and its trailing `\r\n`, leaving the actual chunk data — our smuggled request — untouched in the buffer. We settled on the rule `CL = len(chunk_size_hex) + 2`: the back-end reads the chunk-size digits plus the two bytes of `\r\n`, and nothing more. Two other details bit us early: we needed a trailing `\r\n\r\n` after the closing `0` chunk terminator, or the back-end's chunked parser on subsequent requests would misbehave, and — since we're using raw sockets rather than Burp — there was no "Update Content-Length" checkbox to worry about, but the equivalent mistake (letting a library recompute the header for us) was exactly why we couldn't use `httpx` for this at all.

## The Exploit

The smuggled payload used the same `GPOST` trick as the CL.TE lab — a complete standalone request with an intentionally broken method name, so a clean 404/`Unrecognized method` response on the follow-up request proves the back-end processed our smuggled bytes as its own request:

```
POST / HTTP/1.1
Host: TARGET
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

For the actual lab we substituted our `GPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 10\r\n\r\nx=` request in place of `SMUGGLED`, with the chunk-size and `Content-Length` recalculated to match. We fired this over a raw keep-alive socket, immediately followed by a normal `GET / HTTP/1.1`, and our lab code checked the second response for `Unrecognized method` or a `403` — which is what came back, confirming the back-end had stopped at our truncated `Content-Length`, then parsed the leftover `GPOST` request on its own.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution uses the identical mechanism and lands on the same `GPOST` smuggled request:

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0
```

This is functionally the same payload we sent — a complete smuggled `GPOST` request wrapped in a chunk, with `Content-Length: 4` truncating the back-end's read right after the chunk-size line (`5c\r\n`, 4 bytes). The one procedural note in their solution — "you need to include the trailing `\r\n\r\n` following the final `0`" — is precisely the detail we'd already encoded as a standing rule in our TE.CL payload builder after running into the same failure mode. The delivery difference is the same story as every lab in this set: they issue the request twice by hand in Burp Repeater with "Update Content-Length" unchecked; we computed the exact byte-accurate `Content-Length` in Python and pushed it down a raw socket, which sidesteps needing that checkbox at all since nothing is auto-recalculating our header for us.

## What This Teaches Us

TE.CL is a useful complement to CL.TE precisely because defenders sometimes patch one without realizing the other exists — disabling `Transfer-Encoding` support on the front-end closes CL.TE but does nothing for TE.CL, and vice versa. The chunk-size-plus-two-bytes math here is also a good illustration of just how little slack these attacks need: a `Content-Length` off by even one byte either leaves extra chunk-size digits in the buffer or eats into the smuggled request itself, so precise arithmetic — not just "roughly the right length" — is what makes or breaks the desync. As with CL.TE, the durable fix is to never let a request reach a second parser with an unresolved ambiguity between the two length mechanisms in the first place.
