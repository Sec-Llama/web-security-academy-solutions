# DOM XSS using web messages

**Category:** DOM-Based Vulnerabilities
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages

The `postMessage()` API exists precisely because browsers won't let two windows from different
origins touch each other's DOM directly — it's the sanctioned channel for cross-origin
communication. That makes it an unusually clean vulnerability class to study: the entire attack
surface is "what does the receiving page do with the data it gets handed," because the message
itself never has to pass through the server at all. This lab is the simplest version of that
question — a page that listens for a web message and hands the contents straight to an unsafe
sink.

## The Target

The lab's home page registers a listener for incoming web messages. A normal, benign message is
presumably meant to carry ad content that gets inserted into the page. There's no server-side
component to any of this — the vulnerability, if one exists, lives entirely in client-side
JavaScript that runs after the page has already loaded.

## The Investigation

We ran our DOM sink detector (`detect_dom_sinks` in `DOMBased.py`) against the home page, which
fetches the page and scans inline `<script>` blocks for known source/sink regex patterns —
`addEventListener\s*\(\s*['\"]message['\"]` for the source side, and patterns like
`\.innerHTML\s*=` for the sink side. The scan confirmed a message listener was present and flagged
an `innerHTML`-style sink in the same script. That combination — a message handler feeding
attacker-controlled data into `innerHTML` with no origin check — is exactly the pattern this lab's
category is built around: the handler takes whatever it receives over `postMessage()` and writes
it into a `div` meant to hold ad markup, with no validation of where the message came from and no
sanitization of what it contains.

Since `innerHTML` renders HTML rather than treating it as text, any markup we send arrives on the
page as live DOM. We didn't need `<script>` tags — `innerHTML` assignment doesn't execute those —
but an image tag with a broken `src` and an `onerror` handler fires just as reliably, since the
error event handler is attached to the DOM node itself rather than requiring a parse-time script
execution.

## The Exploit

We used `craft_web_message_xss()` to build the exploit page: an iframe pointing at the lab's home
page that, once loaded, immediately posts a message to it.

```html
<iframe src="https://TARGET/" onload="this.contentWindow.postMessage('<img src=x onerror=print()>','*')"></iframe>
```

The target origin argument is `'*'`, meaning the message is sent regardless of what origin the
iframe's content actually resolves to — which matters only because the receiving page performs no
origin check either, so it accepts the message without complaint. We stored and delivered this
page through the lab's exploit server using the same STORE / DELIVER_TO_VICTIM flow the server's
web form exposes (`_exploit_server_deliver()` posts to those two form actions directly). When the
iframe's `onload` fires, `postMessage()` sends the payload to the home page. The listener there
takes `e.data` and writes it straight into the ads `div` via `innerHTML`. The browser tries to load
an image from a nonexistent path `x`, that request fails, and the `onerror` handler — our injected
JavaScript — runs `print()`, which is PortSwigger's standard proof-of-execution call for these
labs. Because `print()` only fires once the browser has actually parsed and rendered the injected
markup, confirming the solve meant checking the lab's status through a real browser render rather
than trusting the raw HTTP response — the payload never touches the server's response body at all.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's own solution reaches the identical construction: notice the `addEventListener()`
call on the home page, then deliver an iframe via the exploit server with
`onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')"`. The only textual
difference is the placeholder image path — their solution uses `src=1`, ours uses `src=x` — which
is cosmetic; either value is a nonexistent image resource, so both reliably throw the load error
that triggers `onerror`.

The one real difference is delivery mechanics. PortSwigger's walkthrough drives this through the
exploit server's web form manually: paste the iframe HTML into the body field, click "Store," then
"Deliver exploit to victim." Our script sends the same two form submissions programmatically
against the exploit server's HTTP endpoint, which is functionally identical — it's automating the
same two button clicks rather than replacing them with something different.

## What This Teaches Us

The bug here isn't really about `postMessage()` — it's about treating cross-origin input as if it
were trusted internal data. A message handler that writes its payload into `innerHTML` without an
origin check is architecturally the same mistake as a server endpoint that trusts a client-supplied
header: the data crossed a trust boundary and got used as if it hadn't. The fix PortSwigger's own
documentation points to is straightforward and cheap here — check `event.origin` against an exact
allow-list before doing anything with `event.data`, and prefer `textContent` over `innerHTML` when
the data being inserted was never meant to contain markup in the first place. Neither fix costs
meaningful functionality; the ad-serving use case this handler was built for doesn't actually need
either capability it's abusing.
