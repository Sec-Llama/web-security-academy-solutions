# Manipulating WebSocket messages to exploit vulnerabilities

**Category:** WebSockets
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/websockets/lab-manipulating-messages-to-exploit-vulnerabilities

WebSockets carry the same trust problem as every other channel between a browser and a server:
whatever protection the client-side JavaScript adds to outgoing data is cosmetic unless the server
enforces it too. This lab is the cleanest possible demonstration of that gap — a chat widget that
looks safe because the page you're typing into encodes your input, on a server that never checks
what actually arrives over the wire.

## The Target

The lab is an online shop with a live chat feature. Opening the chat opens a WebSocket connection,
and every message typed into the chat box is sent to a support agent in real time over that socket.
A normal chat message travels as a small JSON frame:

```json
{"message":"hello"}
```

The support agent's browser receives that same JSON back and renders the `message` field directly
into the page for them to read.

## The Investigation

The obvious first move is to see what happens to a message containing an angle bracket, since that's
the character any reflected-XSS sink cares about. Typing a `<` into the chat box and watching the
resulting WebSocket frame showed it arriving HTML-encoded — the page's own JavaScript was encoding
the character before the `send()` call ever ran. That's a client-side control, not a server-side
one, and the distinction matters enormously: it only protects input that passes through *that
specific JavaScript*. Anything that opens a WebSocket connection directly and writes to it bypasses
the encoding entirely, because the encoding step lives in code we don't have to execute.

That's exactly what we did — instead of typing into the chat box and letting the page's own script
handle encoding, we connected straight to the WebSocket endpoint from a Python script and wrote the
JSON frame ourselves, with no HTML-encoding step in between our payload and the wire.

## The Exploit

The payload was the standard `onerror`-triggered image tag, sent as the raw JSON value of the
`message` key with no encoding applied:

```json
{"message":"<img src=1 onerror='alert(1)'>"}
```

Sent directly over the WebSocket connection, this frame reaches the server exactly as written. The
server reflects `message` unmodified into the support agent's view, the browser on the receiving end
parses the `<img>` tag, the image fails to load, and the `onerror` handler fires `alert(1)` — solving
the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's own solution reaches an identical payload — `<img src=1 onerror='alert(1)'>` — and even
walks through the same diagnostic step we did: send a `<` through the chat box first, look at the
corresponding WebSocket frame in Burp's WebSockets history tab, and confirm the client is
HTML-encoding it before sending. From there their solution configures Burp Proxy to intercept
WebSocket messages, sends another chat message through the browser, and edits the intercepted frame
in-flight to swap in the raw payload before forwarding it.

That's the one real difference in approach: PortSwigger still routes the payload through the
browser's chat box and rewrites it in Burp's interception window at the last moment, so the
browser's own encoding logic runs and then gets overridden. We skipped the browser and the
encoding step entirely by opening our own WebSocket connection and writing the JSON frame directly —
functionally the same bypass, arrived at by not invoking the vulnerable encoding path at all rather
than intercepting its output.

## What This Teaches Us

The bug here was never really about `<img onerror>` — it's about where the security decision was
made. Encoding user input before sending it over the wire is a UX nicety at best; it does nothing to
protect the party on the *receiving* end unless the server independently validates or encodes what
it reflects. This lab makes that visible by removing the browser from the equation altogether: any
client capable of speaking the WebSocket protocol — a script, a proxy, a hand-rolled socket — can
originate a message the "encoding" JavaScript was never given the chance to touch. The fix is the
same one that applies to reflected XSS anywhere else: encode output at the point it's rendered into
HTML, on the server, regardless of what shape the input arrived in.
