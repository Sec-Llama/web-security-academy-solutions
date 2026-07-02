# Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped

**Category:** Cross-Site Scripting (XSS)
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-onclick-event-angle-brackets-double-quotes-html-encoded-single-quotes-backslash-escaped

Every escaping technique in the previous two labs assumed we were fighting server-side output
encoding. This lab is a reminder that the browser itself performs a decoding pass — HTML entity
decoding — before JavaScript ever sees an attribute's value, and that pass happens regardless of how
carefully the server escaped things for its own encoding scheme.

## The Target

The blog's comment form has a "Website" field that gets stored and later rendered inside an
`onclick` handler on the comment author's name: something like
`onclick="var tracker={track()};tracker.track('WEBSITE_URL');"`. Angle brackets and double quotes are
HTML-encoded, and both single quotes and backslashes are escaped server-side — closing off the
`</script>` route from lab 18 and the escape-the-escape route from lab 19 simultaneously.

## The Investigation

With both the quote and the backslash defended, breaking out of the JavaScript string through
server-side escaping alone looked closed. But the injection point is an HTML attribute value, and
attribute values go through HTML entity decoding by the browser before the JavaScript engine
evaluates the surrounding script — that decoding step happens independently of, and after, whatever
escaping the server applied to protect its own JavaScript syntax. An HTML entity like `&apos;` is
inert as far as the server's JavaScript-string escaping logic is concerned — it's not a literal quote
character, so nothing flags or escapes it — but the browser decodes `&apos;` back into a literal `'`
before handing the attribute's contents to the JavaScript engine.

We initially tried a payload using a literal apostrophe character directly in the URL field
(`http://evil.com?'-alert(1)-'`), and it failed — the server's own escaping caught the literal quote
and backslash-escaped it just like in the earlier labs, since it was reading the raw character, not
an encoded one.

## The Exploit

Switching to the HTML entity form let the payload slip past the server's escaping logic entirely:

```
http://evil.com?&apos;-alert(1)-&apos;
```

stored via the comment form's Website field:

```
POST /post/comment
website=http://evil.com?&apos;-alert(1)-&apos;
```

The server stores and reflects `&apos;` as literal text — it never sees a quote character to escape.
When the browser renders the page and parses the `onclick` attribute, it HTML-decodes `&apos;` back
into `'` before the JavaScript engine reads the attribute string, so the quotes function normally at
execution time even though they were invisible to the server's string-escaping logic the whole way
through. Clicking the comment author's name (which carries the `onclick` handler) fires
`alert(1)`.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the same entity-based technique and payload shape: post a comment,
observe the random string reflected inside the `onclick` handler, then inject
`http://foo?&apos;-alert(1)-&apos;` as the Website value. The mechanism they describe — HTML entities
decoded by the browser before JavaScript evaluation, bypassing server-side quote/backslash escaping —
is exactly what we found. Our domain placeholder differs cosmetically (`evil.com` vs `foo`), which
has no effect on the technique. This is a genuine case of both approaches converging on the same
insight from the same dead end (a literal-quote payload failing first), not a case of solving it
differently.

## What This Teaches Us

Server-side escaping and browser-side decoding are two separate pipelines, and defending only one of
them leaves a real gap: HTML entity decoding happens after the server has finished escaping, so an
entity that represents a dangerous character is invisible to any escaping logic that only looks for
the literal character. This is the mirror image of the "escape the escape" lesson from the previous
lab — here the danger isn't an unescaped escape character, it's an encoding layer the defender didn't
account for at all. The fix is to escape or reject HTML entities in user input before it's placed into
a JavaScript context, or better, avoid mixing untrusted data into inline event-handler attributes in
the first place.
