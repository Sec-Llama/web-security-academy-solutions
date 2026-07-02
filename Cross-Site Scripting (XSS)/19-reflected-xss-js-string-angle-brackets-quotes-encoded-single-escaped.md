# Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped

**Category:** Cross-Site Scripting (XSS)
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-double-quotes-encoded-single-quotes-escaped

The previous lab's `</script>` escape hatch only works if angle brackets survive to the browser
unencoded. This lab closes that hole — `<` and `>` are HTML-encoded — which forces the question back
to whether the JavaScript string itself can still be broken out of, even with quotes escaped.

## The Target

Same reflected search term, same single-quoted JavaScript string context, but this time angle
brackets and double quotes are HTML-encoded on output, and single quotes are backslash-escaped. That
rules out both of the previous two labs' techniques in one move: no `</script>` breakout (angle
brackets are gone) and no direct `';alert(1)//` breakout (the quote gets escaped before it lands).

## The Investigation

With the quote escaped, the natural next question was what exactly the server was doing to produce
that escape. Sending a lone backslash confirmed it: our backslash reached the response completely
untouched. That's the gap — the server escapes single quotes by prefixing a backslash, but it doesn't
escape backslashes themselves. If we send our own backslash immediately before the input the server
will quote-escape, we can make the server's own escaping work against it: our backslash plus the
server's inserted backslash plus our quote resolves, from the JavaScript engine's point of view, to an
escaped backslash followed by an unescaped closing quote.

## The Exploit

Our detection engine flagged this context as backslash-not-escaped despite the single-quote escaping,
but the automated payload crafting misjudged the exact framing for this specific lab, so we
hardcoded the confirmed working payload directly:

```
\';alert(1)//
```

sent as:

```
GET /?search=%5C%27%3Balert(1)%2F%2F
```

The server turns our `\'` into `\\'` in the emitted source — our literal backslash stays a literal
backslash, and the server's inserted backslash pairs with it to form an escaped backslash (`\\`) in
the JavaScript source, leaving our quote unescaped and free to close the string. From there,
`;alert(1)//` runs our call and comments out whatever trailing code the application appends.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the same diagnostic path: submit `test'payload`, observe the single
quote gets backslash-escaped; submit `test\payload`, observe the backslash passes through unescaped.
Their final payload, `\'-alert(1)//`, is functionally identical to ours — both place an unescaped
backslash immediately before the quote so the server's own escape character gets consumed pairing
with our backslash rather than protecting our quote, and both use a JavaScript comment (`//`) to
swallow the trailing code after the injection point. The only wording difference is `-alert(1)` versus
`;alert(1)` as the statement separator, which are equivalent in this position. This is the same
technique arrived at independently, not a case of us following a different path.

## What This Teaches Us

An escape character is only doing its job if it's also protected — the classic "escape the escape"
gap. Backslash-escaping a quote is the right instinct, but if the backslash itself isn't escaped, an
attacker-supplied backslash placed immediately before the delimiter absorbs the defensive escape and
leaves the delimiter free. This is worth internalizing as a general pattern, not just a JavaScript
string quirk: any output-encoding scheme that uses a special character to neutralize another special
character needs to escape that special character too, or the whole scheme collapses under exactly
this kind of adjacent-injection trick.
