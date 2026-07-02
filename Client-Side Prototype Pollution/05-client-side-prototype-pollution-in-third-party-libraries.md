# Client-side prototype pollution in third-party libraries

**Category:** Client-Side Prototype Pollution
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-client-side-prototype-pollution-in-third-party-libraries

Every lab so far in this series had its source and gadget in first-party application code —
something we could read directly. Real applications lean heavily on third-party libraries, though,
and a prototype pollution bug hiding inside a minified dependency is far easier to ship and far
harder to notice than one in code the team wrote themselves. This lab moves the vulnerability into
that territory: a well-known library as the source, and a widely deployed analytics script as the
gadget.

## The Target

The application still logs search activity, but this time through jQuery BBQ's `$.deparam()`
function — a real, commonly used library for parsing structured data out of URL hash fragments —
feeding into a Google Analytics integration (`ga.js`) rather than the app's own logging script.
Because the hash fragment (everything after `#`) is never sent to the server, a source that lives
there is also stealthier than a query-string source: it never appears in server access logs at
all.

## The Investigation

We tested the hash fragment as a pollution source, since jQuery BBQ's `deparam()` is built to
parse it:

```
#__proto__[foo]=bar
```

`Object.prototype.foo` confirmed the pollution. That told us the source was a real, shipped
library function rather than application-specific glue code — which matters, because the same
`$.deparam()` behavior would be present on any site using jQuery BBQ the same way, not just this
lab.

For the gadget side, the lab description itself pointed at the difficulty directly: the gadget is
described as "easy to miss due to the minified source code," and PortSwigger's own recommendation
for this lab is to use DOM Invader rather than manually reading through obfuscated third-party JS.
Working from what the analytics integration on the page actually does, the relevant gadget turned
out to be Google Analytics' `hitCallback` property. `ga.js` calls `hitCallback` as a function after
it finishes sending a tracking beacon — a legitimate feature meant to let a site run code once
analytics data is confirmed sent. If `Object.prototype.hitCallback` holds a string of JavaScript
rather than a function, and the calling code doesn't check the type before invoking it, that string
gets evaluated as code.

## The Exploit

We polluted `hitCallback` via the hash fragment with our XSS payload:

```
#__proto__[hitCallback]=alert(document.cookie)
```

Because the source lives in the URL fragment rather than a query parameter the server sees, we
delivered it through the lab's exploit server rather than typing it directly into the address bar,
navigating the victim's browser to the polluted URL:

```javascript
document.location = "LAB_URL/#__proto__[hitCallback]=alert%28document.cookie%29"
```

When the page loaded with that fragment, `$.deparam()` polluted `Object.prototype.hitCallback`,
the analytics beacon fired, `ga.js` invoked the inherited `hitCallback` as a callback, and
`alert(document.cookie)` executed — solving the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger does not offer a manual walkthrough for this lab at all — its published solution is
DOM Invader only, consistent with the lab description's explicit recommendation that manual
analysis of minified third-party code isn't worth the effort here. Their solution loads the lab in
Burp's browser, enables DOM Invader's prototype pollution scanning, and reports that it "identified
two prototype pollution vectors in the `hash` property" before locating "the `setTimeout()` sink
via the `hitCallback` gadget" — the same `hitCallback` gadget we identified by reasoning about what
the Google Analytics integration on the page does. Their final delivery payload through the
exploit server is functionally identical to ours:

```html
<script>
    location="https://YOUR-LAB-ID.web-security-academy.net/#__proto__[hitCallback]=alert%28document.cookie%29"
</script>
```

This is a case worth naming directly: PortSwigger's own recommended path for this specific lab is
tooling (DOM Invader), not manual source reading, because the whole point of the lab is that manual
analysis of minified third-party code doesn't scale. We reached the same source and gadget without
DOM Invader, by reasoning from what the analytics library is documented to do rather than
reverse-engineering its minified source line by line — a reminder that knowing a library's public
API surface can substitute for reading its obfuscated implementation.

## What This Teaches Us

Prototype pollution gadgets don't have to live in code your team wrote — a widely used library
(jQuery BBQ) supplied the source, and another widely used one (Google Analytics) supplied the
gadget, and neither was written with this application's threat model in mind. That's the real risk
of third-party dependencies for this vulnerability class: a gadget shipped in a library you didn't
audit can turn a source elsewhere on the page into full DOM XSS, and because the library code is
minified, the gadget is far less likely to be caught by manual review than the same pattern would
be in first-party code. Hash-fragment sources compound the problem because they're invisible to
server-side logging and monitoring entirely — the only way to catch this class of bug is testing
the client-side behavior directly, not auditing request logs.
