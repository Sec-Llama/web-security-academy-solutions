# Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped

**Category:** Cross-Site Scripting (XSS)
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-template-literal-angle-brackets-single-double-quotes-backslash-backticks-escaped

By this point in the series the pattern is familiar: find the character that closes the current
string context, and see what the application forgot to escape. This lab picks a JavaScript template
literal as the context and escapes everything we'd normally reach for — including the backtick
itself. The gap turns out not to be a character at all, but a piece of template-literal syntax.

## The Target

The search term is reflected inside a JavaScript template literal — something like
`` var x = `INPUT`; `` — with angle brackets, single quotes, double quotes, backslashes, and backticks
all Unicode-escaped on output (`` ` `` becomes ```, and so on). Every character we'd need to
close the literal and inject a new statement was neutralized.

## The Investigation

Template literals aren't just string literals with a different delimiter — they support `${}`
interpolation, which evaluates a JavaScript expression inline and substitutes its result into the
string, all without ever needing to close and reopen the surrounding backticks. That's a different
category of primitive from the single/double-quoted strings in the earlier labs: since `${}` doesn't
require breaking out of the literal at all, escaping the backtick is irrelevant to it. As long as our
`$`, `{`, and `}` characters reach the page unescaped — and none of them were on this filter's escape
list — the expression inside gets evaluated as live JavaScript regardless of how well-defended the
surrounding backticks are.

## The Exploit

We sent the interpolation expression directly as the search term:

```
${alert(1)}
```

as:

```
GET /?search=%24%7Balert(1)%7D
```

The reflected template literal became `` var x = `${alert(1)}`; ``, and the JavaScript engine
evaluated `alert(1)` as part of building the template string, firing the alert regardless of the
Unicode-escaping applied to every quote and backtick character around it.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution is the identical payload and identical reasoning: submit a random string,
observe it lands inside a JavaScript template string, then replace it with `${alert(1)}` to execute
code inside the template literal. This matches our approach exactly — there's no meaningful technique
divergence here, since `${}` interpolation is the one documented way to run code inside a template
literal without needing to close it, and both approaches landed on it directly. As with the rest of
this series, the difference is purely in delivery: their walkthrough is manual through Burp Repeater
and a browser, ours was scripted end to end.

## What This Teaches Us

Escaping a set of "dangerous characters" only closes the paths that require those characters — it
does nothing against a language feature that doesn't need them. Template literal interpolation is the
clearest example in this series of a syntax feature living entirely inside the delimiters an escaping
scheme was trying to protect. The fix isn't a longer escape list; it's not reflecting untrusted input
into a JavaScript template literal context at all, or, if unavoidable, encoding `$` and `{` as well as
the quote/backtick characters so `${}` sequences can never be reconstructed from reflected input.
