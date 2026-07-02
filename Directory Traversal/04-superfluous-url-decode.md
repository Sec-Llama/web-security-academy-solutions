# File path traversal, traversal sequences stripped with superfluous URL-decode

**Category:** Directory Traversal
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/file-path-traversal/lab-superfluous-url-decode

Every layer that decodes a request is a layer that can be tricked into decoding it twice. This
lab strips `../` sequences and then, somewhere later in its processing, URL-decodes the value a
second time — which means a payload encoded twice survives the strip disguised as something
harmless, then reveals itself only after the extra decode the application didn't need to do. It's
also the lab in this series where our own tooling ended up doing something unplanned that turned
out to matter.

## The Target

The familiar `GET /image?filename=` image loader, this time defended by a filter that strips
`../` sequences and then performs a superfluous additional URL-decode pass on what's left.

## The Investigation

Basic, absolute, and nested payloads all failed against this lab — the strip is applied
correctly and only once, so the previous lab's bypass doesn't work here. The detector moved on to
its URL-encoded payload class: `%2e%2e%2f` repeated six times, followed by `etc%2fpasswd`, sent
through `httpx`'s standard `params={}` request builder.

That payload came back verified — but not for the reason we expected going in. `httpx`'s
`params` dict encodes its values before putting them on the wire, and part of that encoding is
percent-encoding the literal `%` character itself into `%25`. So a string we constructed as a
*single* URL-encoded payload (`%2e%2e%2f...`) left our script as one thing and arrived at the
server as another: every `%2e` became `%252e` on the wire, which is a *double*-encoded sequence.
That's exactly the shape this lab needs — the app's strip pass sees `%252e%252e%252f`, doesn't
recognize it as `../`, lets it through, and only the superfluous second decode turns it into a
real traversal sequence. We got the correct bypass largely because our HTTP client's own encoding
behavior happened to match what the target's decode-twice bug required.

To confirm that wasn't a fluke, we separately sent a manually double-encoded string directly —
`..%252f..%252f..%252fetc/passwd` — bypassing `params={}` entirely, and that also verified
against the same endpoint.

## The Exploit

Both of the following were confirmed working against this lab:

```
GET /image?filename=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```
sent through `httpx`'s `params={}` dict (which re-encodes the `%` into `%25` on the wire, so the
server actually receives a double-encoded value), and directly:

```
GET /image?filename=..%252f..%252f..%252fetc/passwd
```

Either request produced a response containing `/etc/passwd`, matched by our confirmation regex,
and the lab flipped to solved.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's published solution uses the second form directly:
`..%252f..%252f..%252fetc/passwd`, typed into Burp Repeater exactly as written. Burp doesn't
re-encode the `%` character the way a scripted client library building a query string from a
dict can, so their payload has to be double-encoded explicitly by hand.

We landed on the same bytes on the wire, but by a different and honestly half-accidental path:
letting `httpx` build the request from a plain single-encoded string, and having its own
parameter-encoding logic do the second layer of encoding for us. This is a genuine tooling
difference worth calling out rather than smoothing over — it's not that we found a smarter
technique, it's that the abstraction layer between "the string in our script" and "the bytes on
the wire" quietly did the double-encoding step that PortSwigger's manual solution does on
purpose. Once we noticed that, we verified the payload directly too, so the finding doesn't rest
on the accident.

## What This Teaches Us

The vulnerable pattern is decoding the same value more than once anywhere in the request
pipeline — every additional decode pass is another chance for an already-cleaned string to turn
back into something dangerous. But this lab is also a useful reminder about tooling: an HTTP
client's own request-building behavior is part of what actually reaches the server, not just the
string an operator typed. Whether you're defending against this bug or trying to reproduce a
report of it, the safe fix is unchanged — decode exactly once, as early as possible, and run
every validation and canonicalization step after that single decode, never before it.
