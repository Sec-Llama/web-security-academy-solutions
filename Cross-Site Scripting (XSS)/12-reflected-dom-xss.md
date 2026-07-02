# Reflected DOM XSS

**Category:** Cross-Site Scripting (XSS)
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-reflected

This lab folds two ideas from earlier labs together: a reflected value (the search term shows up in
an HTTP response, this time as JSON rather than HTML) and a JavaScript-parsing sink (`eval()`) that
the response feeds into on the client side. Neither half is new on its own, but the combination — a
JSON API response getting `eval()`'d as if it were trusted code — is a pattern worth recognizing on
sight, since it shows up constantly in real applications that predate safer alternatives like
`JSON.parse()`.

## The Target

The search page issues a background request to a `search-results` endpoint that returns the search
term inside a JSON body, something like `{"results":[],"searchTerm":"INPUT"}`. Client-side JavaScript
in `searchResults.js` takes that response text and runs it through `eval()` to turn it into a usable
object.

## The Investigation

The interesting part of this lab isn't finding that the search term is reflected — it's finding
*where* it's reflected and what consumes it. Watching the actual network traffic (rather than just
the initial page's HTML) showed the search term coming back inside a JSON response, and following
that response into `searchResults.js` showed it being handed to `eval()` as part of a larger string:
effectively `eval('var data = ' + responseText)`. That means our payload doesn't need to satisfy an
HTML or attribute grammar at all — it needs to be valid inside a JSON string value that, once
concatenated into JavaScript source and evaluated, breaks out of that string.

We probed the JSON encoding by testing a double quote and a backslash separately: the double quote
came back properly escaped (`\"`), which is what you'd expect from correct JSON serialization — but
the backslash itself was not escaped. That asymmetry is the vulnerability: a literal backslash we
supply gets treated by the JSON encoder as an escape character for whatever comes right after it,
which we can use to neutralize the encoder's own escaping of the following quote.

## The Exploit

We submitted a search term designed to abuse that backslash asymmetry:

```
\"-alert(1)}//
```

Because our leading backslash isn't itself escaped by the response's JSON serialization, it combines
with the double quote the server *does* insert to close our string value into an escaped-but-broken
sequence — the net effect, once the resulting string reaches `eval()`, is that the JSON string
terminates early, `-alert(1)` executes as a subtraction/function-call expression, and `}` plus a
line comment (`//`) absorb whatever trailing JSON syntax the application appends, so the rest of the
line never throws a syntax error.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution walks through Burp Suite's Proxy and Site Map to find the `search-results`
JSON response and the `searchResults.js` file that `eval()`s it, then identifies the same
quote-escaped-but-backslash-not-escaped asymmetry through experimentation, arriving at the exact
same payload: `\"-alert(1)}//`. This is a full match on both technique and payload. The investigative
process is naturally the same too — there's really only one way to notice this bug, which is tracing
the response through to its consuming JavaScript rather than stopping at the HTTP response body. The
difference, as throughout this series, is tooling: their walkthrough traces the flow through Burp's
Proxy/Site Map UI, we traced it by fetching and diffing the JSON response and the JS file
programmatically.

## What This Teaches Us

`eval()` on a server response is dangerous even when that response is "just JSON," because JSON's
safety guarantee only holds if it's parsed with something that actually enforces JSON grammar —
`JSON.parse()`, not `eval()`. The moment a JSON string is concatenated into a larger JavaScript
expression and evaluated as code, any escaping gap in how that string was serialized (here: quotes
escaped, backslashes not) becomes a code-execution primitive rather than just a data-integrity bug.
The fix is two-fold: use `JSON.parse()` instead of `eval()` for any JSON response, which sidesteps
this entire class of injection regardless of encoding correctness, and independently fix the response
serialization itself so both quotes and backslashes are properly escaped.
