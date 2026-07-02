# Reflected XSS in a JavaScript URL with some characters blocked

**Category:** Cross-Site Scripting (XSS)
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-url-some-characters-blocked

A `javascript:` URL is already live code, not a string waiting to be escaped out of — which makes it
feel like the easiest possible injection point. This lab shows that even there, a character filter can
force a genuinely creative rewrite of what should be trivial JavaScript, because two of the characters
it blocks are the space character and (effectively) any straightforward use of `throw`.

## The Target

The blog post page has a "Back to Blog" link built as a `javascript:` URL:
`javascript:fetch('/analytics?endpoint=PARAM')`, with `PARAM` reflecting a URL parameter into the
argument passed to `fetch()`. Since this is already a `javascript:` context, no HTML or string-escaping
tricks are needed to get code execution — the challenge is entirely about which JavaScript we're
allowed to write, given the application blocks spaces and several other characters we'd normally
reach for.

## The Investigation

The immediate obstacle was closing the existing `fetch('/analytics?endpoint=...')` call and getting our
own statement to run in its place — straightforward in principle, `'),alert(1),('` -style breakouts are
common — but calling `alert(1337)` as a plain expression wasn't the issue; the issue was doing it
without a single space character anywhere in the payload, since the filter strips them.

`throw` solves the "how do I signal an error with a custom value" half of the problem, since we can
throw `1337` and have it delivered to a handler, but `throw` is a *statement*, not an *expression* —
it can't be used inline the way `fetch(...)` expects an expression as its argument. Wrapping it in an
arrow function body (`x=>{throw 1337}`) turns the statement into something callable, sidestepping the
expression/statement restriction. Comment syntax (`/**/`) works as a substitute for the literal space
character between tokens like `throw` and `onerror`, since JavaScript treats a comment the same as
whitespace for tokenization purposes. The last piece was actually *triggering* that thrown value:
assigning our arrow function to `window`'s `toString` method and then forcing a string coercion on
`window` (`window+''`) calls `toString()` implicitly, which invokes our function, which throws — and
because we'd also set `onerror` to `alert` via the comma operator before the throw, the thrown value is
delivered straight into `alert()`.

## The Exploit

```
'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:'
```

sent as:

```
GET /post?postId=5&'},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b'',{x:'
```

This closes the original `fetch('/analytics?endpoint=` argument (`'}`), then chains a sequence of
comma-separated assignments: define `x` as an arrow function that (via the comma operator) sets
`onerror=alert` and then throws `1337`; assign that function to `window.toString`; force `window+''` to
trigger the coercion and invoke `toString()`; the final `,{x:'` re-opens an object literal shape so the
remainder of the original line still parses without a syntax error. The result only fires on
navigation — the lab notes the alert triggers specifically when the "Back to Blog" link is clicked,
since that's what actually evaluates the `javascript:` URL. We drove a headless browser to the crafted
URL and clicked the "Back to Blog" link to confirm the alert fired.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution is the identical payload:
`https://YOUR-LAB-ID.web-security-academy.net/post?postId=5&%27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27`,
with the identical explanation of every moving part — `throw` as a statement requiring an arrow
function wrapper to act as an expression, `/**/` replacing the blocked space character, `onerror=alert`
assigned via the comma operator before the throw, and the `toString` override forcing execution via
`window+''` string coercion. This is a byte-for-byte match. Given how specific and non-obvious this
construction is, landing on the identical payload independently is strong confirmation we reasoned
through the same constraint chain PortSwigger designed the lab around, not a coincidence of simpler
payload space.

## What This Teaches Us

Even a context that's already executable JavaScript — no HTML encoding, no string-quote escaping
needed — can still be meaningfully hardened by restricting the character set available to an attacker,
and character-level filters can be surprisingly effective right up until someone finds the specific
combination of comma operators, comment-as-whitespace, and implicit type coercion that reconstructs
the missing functionality from allowed primitives. The specific techniques here — `throw` inside an
arrow function to use it as an expression, `/**/` as a space substitute, forcing `toString()` invocation
via coercion — are worth keeping as a toolkit for any future "some characters blocked" JavaScript
context, because they don't depend on this application's specific filter; they're general JavaScript
mechanics that happen to route around the two most commonly blocked characters (spaces and certain
statement keywords) in exactly this class of filter.
