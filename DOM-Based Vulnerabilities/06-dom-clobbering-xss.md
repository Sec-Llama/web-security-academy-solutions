# Exploiting DOM clobbering to enable XSS

**Category:** DOM-Based Vulnerabilities
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-xss-exploiting-dom-clobbering

DOM clobbering is the odd one out in this series because there's no `postMessage()`, no cookie, no
attacker-controlled URL parameter at all — the attack surface is a quirk of how HTML `id` and
`name` attributes automatically become named properties on `window` and on their parent elements.
This lab pairs that quirk with DOMPurify, a sanitization library trusted by a huge number of
production applications as the last line of defense against exactly the kind of markup injection
this lab is built around — which is what makes bypassing it, rather than a homegrown filter,
worth the extra attention.

## The Target

The site runs a comment system. Comments are sanitized through DOMPurify 2.0.15 before being
rendered, which should strip dangerous attributes and scripts from anything a user posts. The
comment-rendering script includes a pattern common in real applications: a fallback initializer,
`let defaultAvatar = window.defaultAvatar || {avatar: '/resources/images/avatarDefault.svg'}`,
followed by code that builds an avatar `<img>` tag using `defaultAvatar.avatar` as the `src`
attribute value.

## The Investigation

The fallback pattern `window.someGlobal || {}` is the exact shape DOM clobbering targets: if
`window.defaultAvatar` already exists — as *any* value, not necessarily an object the developer
intended — the `||` short-circuits and that existing value gets used instead of the safe default
object. HTML elements with an `id` attribute automatically become accessible as named properties on
`window` (a legacy browser behavior for backward compatibility), which means we don't need any
script execution to set `window.defaultAvatar` — injecting an element with that `id` into the page
is enough.

A single anchor with `id=defaultAvatar` would clobber the variable with a reference to that DOM
node, but `defaultAvatar.avatar` on a lone anchor element wouldn't resolve to anything useful. Two
anchors sharing the same `id` instead produce an `HTMLCollection` — a small quirk of how browsers
resolve duplicate IDs — and named sub-properties on elements inside that collection (via their
`name` attribute) become accessible as properties of the collection itself. So a second anchor with
`name=avatar` and an `href` becomes reachable as `defaultAvatar.avatar`, resolving to that anchor's
`href` value — exactly the property the vulnerable code reads.

That still leaves DOMPurify in the way: it sanitizes the comment before it's stored, and would
normally strip a `javascript:` URL from an `href`. DOMPurify 2.0.15 whitelists the `cid:` URL scheme
(used for referencing MIME content-IDs, a legitimate but rarely used protocol) as safe, so it
passes an `href` starting with `cid:` through unmodified. Combined with `&quot;`, which the browser
decodes to a literal `"` character once the attribute value is parsed, this lets the `href` value
break out of the `src="..."` attribute it eventually gets written into by the avatar-rendering code
— `cid:` satisfies DOMPurify's URL check, and the embedded `&quot;` does the actual attribute
escape once the value is used, downstream, in a context DOMPurify never re-sanitizes.

One more piece mattered: the clobbering only has an effect the *next* time the avatar-rendering
code runs and reads `window.defaultAvatar`, not retroactively on comments already rendered on the
page. A single comment containing the clobbering payload sits there but doesn't trigger anything
by itself — a second, unrelated comment causes the page to re-render its comment list (including
avatars), and that re-render is what actually reads the now-clobbered global and uses it.

## The Exploit

The clobbering payload, from `craft_dom_clobbering_comment()`, posted as one comment:

```html
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
```

Followed by a second, unrelated comment with arbitrary trigger content ("Trigger comment" in our
run) to force the page to re-render its comment list. The next time the avatar HTML gets built,
`defaultAvatar.avatar` resolves to the clobbered anchor's `href`, the avatar `<img src="...">` tag
is constructed with our `cid:&quot;onerror=alert(1)//` value, the embedded `&quot;` closes the `src`
attribute early, and `onerror=alert(1)` becomes a live attribute on the `img` tag. The browser
attempts to load `cid:` as an image source, fails, and the `onerror` handler runs `alert(1)`.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution uses the identical two-anchor payload and the identical two-comment
sequence — post the clobbering anchors as one comment, then post any second comment to trigger a
fresh render. The payload strings match exactly, including the use of `alert(1)` specifically
(rather than `print()`, which the earlier labs in this series use) as the proof-of-execution call
for this particular lab. There's no technique divergence here — this is a case where the mechanism
is precise enough (a specific browser quirk plus a specific DOMPurify version behavior) that there's
really only one payload shape that works. The difference, as with the other exploit-server-free
labs in this series, is that PortSwigger's walkthrough has you type the comments into the blog's
comment form by hand, while our script posted both comments via direct HTTP requests to the
`/post/comment` endpoint.

## What This Teaches Us

DOM clobbering is a reminder that a sanitizer can do everything it's designed to do — DOMPurify
correctly permitted a URL scheme that is, in the abstract, safe — and still be bypassed if the
*consuming* code trusts a value's type without checking it. `window.defaultAvatar || {}` assumes
that if `window.defaultAvatar` is truthy, it's the object the developer created; DOM clobbering
breaks exactly that assumption by making an unrelated DOM structure satisfy the truthiness check
while returning something entirely different in shape. The fix isn't a better sanitizer
configuration — it's not trusting global lookups that can be influenced by page content at all: use
a properly namespaced module-scoped variable instead of a bare `window` property, and validate that
any object read from a global actually has the expected shape (e.g. `typeof defaultAvatar.avatar
=== 'string'` isn't even enough — checking it's not a DOM node matters here) before using its
properties in a sink.
