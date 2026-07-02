# Manipulating the WebSocket handshake to exploit vulnerabilities

**Category:** WebSockets
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/websockets/lab-manipulating-handshake-to-exploit-vulnerabilities

A WebSocket connection starts life as an ordinary HTTP request — the "handshake" — before it
upgrades to the full-duplex protocol. That handshake carries the same headers as any other HTTP
request, including whichever ones an application has decided to trust for security decisions. This
lab pairs an XSS filter on the message content with an IP-based ban on the handshake itself, and the
second control turns out to trust a header an attacker can simply set.

## The Target

Same live chat feature as the previous lab, same JSON-over-WebSocket message format — but this time
the server actively inspects outgoing chat messages for XSS and responds aggressively: a detected
attack doesn't just get dropped, it terminates the WebSocket connection and bans the originating IP
address from reconnecting.

## The Investigation

Sending the same payload that worked in the previous lab —
`<img src=1 onerror='alert(1)'>` — got the connection killed immediately, confirming an active
filter rather than a silent drop. Trying to reconnect afterward failed outright: the handshake itself
was being rejected, which meant the ban was keyed to something in the handshake request rather than
to the WebSocket session. The obvious candidate for a header-based IP control on a handshake is
`X-Forwarded-For`, so we added it to the next handshake attempt with a fresh value — a technique
that worked cleanly once we sorted out a version mismatch in the WebSocket library itself. The
Python `websockets` library changed its header-injection API between major versions: v13+ expects
`extra_headers=` on `websockets.connect()`, not the older `additional_headers=` parameter or the
deprecated `websockets.client.connect()` entry point. Getting a custom header into the handshake at
all depended on using the current API correctly.

With the IP ban bypassed by reconnecting with a spoofed `X-Forwarded-For`, the filter on the message
content itself was still standing between us and a working `alert()`. Sending the plain payload
again confirmed the filter was still active even from the new IP — it was inspecting message content
independent of the ban logic. That meant the filter had to be dissected on its own terms: what
exactly was it matching? Testing individual pieces narrowed it to two independent checks — a
case-sensitive match on lowercase event-handler attributes (`on[a-z]+=`), and a separate match on the
literal string `alert`. Both had to be defeated at once, and defeating one without the other still
got the connection killed.

The event-handler check falls to mixed case: `onerror` written as `oNeRrOr` still parses as a valid
event-handler attribute in HTML (attribute names are case-insensitive to the browser) but no longer
matches a filter that only checks for the lowercase pattern. The `alert` check is a literal string
match, so anything that produces the same function call without the substring `alert` appearing
intact defeats it. We tried several ways to reconstitute the call at runtime: string concatenation
inside a bracket-property lookup, a hex-escaped character in the same lookup, `eval` with a
concatenated string, and the `Function` constructor with a concatenated string — building a small set
of payload variants rather than gambling everything on one obfuscation trick.

## The Exploit

The full attack chain: send an unobfuscated payload to confirm the filter and trigger the ban, then
reconnect with a spoofed `X-Forwarded-For` header in the handshake, then send an obfuscated payload
that defeats both filter checks simultaneously. Our verified working payload combined the mixed-case
handler with string-concatenation to reconstruct `alert` without ever writing the literal word:

```
X-Forwarded-For: 127.0.0.1
```

```json
{"message":"<img src=1 oNeRrOr=window['al'+'ert'](1)>"}
```

`window['al'+'ert']` evaluates to `window['alert']` at runtime — the same function reference as
`window.alert` — so the browser still calls the real `alert()` function, but the string `alert` never
appears intact anywhere in the payload the filter inspects. Combined with the mixed-case `oNeRrOr`
handler, the message passed the filter, reached the support agent's browser, and fired the popup.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the handshake bypass the identical way — send the plain XSS payload
through Burp's WebSockets history to confirm the ban, observe the reconnect failing, then add
`X-Forwarded-For: 1.1.1.1` to the handshake request (edited and resent through Burp's Repeater) to
spoof past the IP ban. That part of the chain matches exactly, IP address chosen aside.

The obfuscation payload is where our paths genuinely diverge. PortSwigger's published solution uses
a tagged template literal — `` <img src=1 oNeRrOr=alert`1`> `` — which calls `alert` with the
argument `1` using template-literal syntax instead of parentheses, avoiding the `alert(` substring a
naive filter might match on parentheses specifically. Our working payload instead avoided the
`alert` *string itself* by reconstructing it at runtime via `window['al'+'ert'](1)`, which implies
the filter we were up against was matching on the bare word `alert` rather than on `alert(`. Both
payloads defeat a keyword-matching filter, but they defeat different assumptions about what the
filter is actually looking for — tagged templates dodge a parenthesis-focused check, string
concatenation dodges a substring-focused check. That we built and tried several obfuscation variants
(hex escape, `eval`, `Function` constructor) rather than committing to one is really a hedge against
not knowing in advance which of those two filter shapes we'd be facing.

## What This Teaches Us

Two separate design flaws stacked on top of each other here, and each one independently breaks
security controls that look reasonable in isolation. Trusting `X-Forwarded-For` for a ban is trusting
a header the client controls completely — it exists for proxies to report a real client IP, not for
clients to assert one, and any application that uses it as an identity or reputation signal without
validating it against the actual TCP peer is trivially bypassable. The XSS filter fails for the more
general reason every keyword-based filter eventually fails: matching literal substrings like `alert`
or `on[a-z]+=` catches the payload you thought of, not the property of the payload that actually
matters, which is "does the browser execute this as script." Case-insensitive HTML attribute parsing
and JavaScript's own flexibility for constructing function references at runtime both undermine any
filter built on fixed strings — the fix, as always, is output encoding and a strict content security
policy rather than pattern matching against known-bad substrings.
