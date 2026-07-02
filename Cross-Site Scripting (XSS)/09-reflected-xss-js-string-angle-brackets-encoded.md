# Reflected XSS into a JavaScript string with angle brackets HTML encoded

**Category:** Cross-Site Scripting (XSS)
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-html-encoded

This lab moves the injection point somewhere new: inside a JavaScript string literal embedded
directly in the page, rather than in HTML markup or an attribute value. That's a meaningfully
different context — the browser isn't looking for tags or attributes here, it's looking for the end
of a quoted string inside a `<script>` block, and angle-bracket encoding is completely irrelevant to
that parser.

## The Target

The search functionality again, but this time the search term is echoed into an inline `<script>`
block as part of a JavaScript variable assignment — something like `var searchTerm = 'INPUT';` —
rather than into the HTML body or an attribute.

## The Investigation

Classifying the reflection context here meant looking for the value inside a `<script>` tag rather
than an HTML tag or attribute, which our detection logic flags separately. Once confirmed as a
JavaScript-string context, we probed the same filter characters as always: angle brackets came back
encoded, but the single quote delimiting the string was reflected completely unescaped. That's the
whole story for this lab — a JS string context cares about the quote character that opens and closes
it, not about angle brackets, which have no special meaning to the JavaScript parser at all.

## The Exploit

We closed the string with an unescaped single quote, added a statement, and commented out whatever
JavaScript follows in the original source:

```
';alert(1)//
```

Delivered as:

```
GET /?search=%27%3Balert(1)%2F%2F
```

This turned `var searchTerm = 'INPUT';` into `var searchTerm = '';alert(1)//';`. The first `'`
closes our string, the `;` ends the (now-empty) assignment statement, `alert(1)` runs as its own
statement, and `//` comments out the trailing `';` the application appends after our input — so the
rest of the line never causes a syntax error.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's published solution submits a random string to confirm it lands inside a JavaScript
string, then replaces it with `'-alert(1)-'` to break out of the string and call `alert()`. That's a
slightly different construction from ours — they close the string, subtract `alert(1)`'s return value
(`undefined`, coerced to `NaN`) from the empty string on either side, and rely on the remainder of the
line still being syntactically valid rather than commenting it out. Both payloads exploit the exact
same underlying weakness (the single quote isn't escaped, so it terminates the string early), they
just handle the trailing JavaScript differently — theirs folds it into a harmless expression, ours
comments it out entirely. Either approach is valid; which one works can depend on exactly what code
follows the injection point in a given target, so having both techniques available is useful in
practice.

## What This Teaches Us

HTML-encoding is a defense against an HTML parser, and it does nothing against a JavaScript parser
reading a `<script>` block — the two have completely different special characters and completely
different escape mechanisms. A single quote inside a JS string is dangerous in exactly the same way
an unescaped double quote is dangerous inside an HTML attribute: it lets an attacker redefine where
the "trusted" region ends. The fix for this context is JavaScript string escaping — backslash-escape
quotes, backslashes, and line terminators before embedding user data inside a script block — and,
more robustly, avoid writing user data directly into inline script at all in favor of passing it
through a `data-*` attribute or a JSON-encoded value read by the script rather than concatenated into
it.
