# HTTP request smuggling, basic CL.TE vulnerability

**Category:** HTTP Request Smuggling
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te

Request smuggling went from a curiosity to one of the most consequential bug classes in web security after James Kettle's 2019 "HTTP Desync Attacks" research showed that the disagreement between a front-end and back-end server over where one HTTP request ends and the next begins isn't a parsing quirk — it's a way to inject an entire attacker-controlled request directly onto someone else's connection. This lab is the simplest possible version of that idea: two servers that both understand `Content-Length` and `Transfer-Encoding`, but trust different ones.

## The Target

The lab sits behind a front-end/back-end pair. The front-end doesn't support chunked encoding at all, and it rejects any request that doesn't use `GET` or `POST`. That second detail turns out to be the win condition: if we can make the back-end server interpret part of our request as the start of the *next* request, and that next request appears to use some method other than `GET`/`POST`, we've proven the back-end desynced from the front-end.

## The Investigation

The setup is the textbook CL.TE case: the front-end forwards bytes according to `Content-Length`, while the back-end parses the body as chunked because `Transfer-Encoding: chunked` is present. If we send a request with both headers, and the back-end's chunked parser hits its terminating `0\r\n\r\n` sequence before the front-end's `Content-Length` count runs out, whatever bytes are left over sit in the back-end's buffer waiting to be interpreted as the beginning of the next request on that connection.

Two things had to be true in our tooling before this would work at all. First, standard HTTP libraries like `httpx` and `requests` normalize headers and refuse to send a body that doesn't match a sane `Content-Length` — they actively fight this attack. We had to drop to raw TLS sockets with `ALPN: http/1.1` negotiated manually to get bytes on the wire exactly as written. Second, header order mattered: we send `Transfer-Encoding` before `Content-Length` in the header block, on the theory that a front-end scanning top-to-bottom for a length header stops at the first match it sees (`Content-Length`, since it doesn't support chunked), while the back-end's parser finds `Transfer-Encoding` first and honors that instead. Whether or not that's exactly the mechanism in this particular lab, sending TE before CL is what we verified working, and we kept it as a standing rule for every CL.TE payload after.

## The Exploit

We smuggled a complete, self-contained request whose method is deliberately mangled — `GPOST` instead of `POST` — so that if it lands as the start of a genuine request that the back-end parses independently, the response gives us an unambiguous signal:

```
POST / HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 13
Transfer-Encoding: chunked

0

GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

We sent this over a raw keep-alive connection immediately followed by a normal `GET / HTTP/1.1`. Our lab-solving code explicitly checks the response to that follow-up for the substring `Unrecognized method` (or a `403`) — and that's exactly what came back. The back-end had stopped at the chunked terminator, left `GPOST / HTTP/1.1...` sitting in its buffer, and when the real follow-up request's bytes never arrived to complete it in the way the back-end expected, it processed the smuggled request as its own and rejected the bogus method. That's proof positive of a CL.TE desync.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the same conclusion with a more economical payload. Instead of smuggling a complete, self-contained `GPOST` request, they smuggle a single byte:

```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

The trick is that this lone `G` gets left in the back-end's buffer, and when Burp Repeater sends the *exact same request again* on the same connection, its own request line — `POST / HTTP/1.1` — gets appended right after that dangling `G`, producing `GPOST / HTTP/1.1` on the back-end's side. It's the same desync mechanism we found, but they let the second copy of the *original* request supply the "OST" while we smuggled a complete, independent request that didn't need anything from what came after it. Both are valid: ours is slightly more verbose but self-contained and easier to reason about programmatically; theirs is minimal and relies on issuing the identical request twice, which is trivial to do by hand in Repeater. The bigger difference is delivery — their solution is driven entirely through Burp Repeater's manual "send twice" workflow, while ours ran through a Python script over a raw socket, which is the only way to get non-conformant `Content-Length`/`Transfer-Encoding` combinations onto the wire without a library rewriting them first.

## What This Teaches Us

The vulnerability isn't a bug in either server individually — both correctly implement a header they were told to trust. The bug is architectural: two independent HTTP parsers, disagreeing about the same byte stream, with no way for either one to know the other reached a different conclusion. That's why the fix isn't "patch the parser" so much as "stop having two parsers disagree" — RFC 7230 says that when both `Content-Length` and `Transfer-Encoding` are present, `Transfer-Encoding` should take priority and `Content-Length` should be removed or rejected, but this lab exists precisely because not every real-world server follows that rule the same way. The practical fix is to normalize or reject ambiguous requests at the front-end before they ever reach a second parser that might read them differently.
