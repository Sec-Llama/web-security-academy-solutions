# Reflected XSS into a JavaScript string with single quote and backslash escaped

**Category:** Cross-Site Scripting (XSS)
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-single-quote-backslash-escaped

Escaping the single quote is the obvious first defense against breaking out of a JavaScript string
literal, and by itself it works. The mistake this lab tests for is subtler: escaping the quote
without also escaping the character that makes the escape mean anything.

## The Target

The search term is reflected inside an inline `<script>` block as a single-quoted JavaScript string,
something like `var trackingId = 'INPUT';`. A quick probe confirmed the server backslash-escapes any
single quote in our input before inserting it — `'` becomes `\'` in the response — which should
prevent it from closing the string.

## The Investigation

Escaping a quote only protects the string if the escaping character itself can't be neutralized.
Since the server was adding a backslash in front of our quote but not touching backslashes we sent
ourselves, we didn't need to fight the escaping directly — we could go around the JavaScript string
context entirely. The reflection point sits inside a `<script>` block, and `</script>` closes that
block regardless of what string logic is happening inside it; the browser's HTML parser reads
`</script>` before the JavaScript engine ever gets a chance to evaluate the string it's sitting in.

## The Exploit

Our engine's Layer 1 detector confirmed the JS-string context with quotes escaped, and Layer 2
crafted the corresponding payload:

```
</script><script>alert(1)</script>
```

sent as:

```
GET /?search=%3C%2Fscript%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E
```

The leading `</script>` terminates the original script block before our injected quote or its
escaping ever matters, and the new `<script>alert(1)</script>` that follows executes as an entirely
separate block.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's own solution reaches the identical payload through identical reasoning: submit a test
string, observe the single quote gets backslash-escaped and can't break out of the string, then use
`</script><script>alert(1)</script>` to close the existing script block and inject a fresh one. This
matches our approach exactly, including the underlying insight that HTML tag boundaries are parsed
independently of whatever JavaScript string logic is happening inside them. As with the rest of this
series, the only difference is delivery — their walkthrough is manual through Burp Repeater, ours
was driven by our detection/craft engine and confirmed with a headless browser.

## What This Teaches Us

Escaping the delimiter character is necessary but not sufficient — if the escape character itself can
still be injected and isn't neutralized, an attacker can use it against the encoding, or, as here,
simply step outside the context the encoding was meant to protect. `</script>` closing an active
script block is a structural fact about how browsers parse HTML, independent of anything the
JavaScript inside that block is doing, and no amount of correct string-escaping inside the block
defends against it. The fix has to happen at the boundary: either encode `<` and `>` on output so
`</script>` can never appear literally in the reflected value, or move dynamic values out of inline
`<script>` blocks entirely and into a JSON payload consumed by separately-loaded JavaScript.
