# File path traversal, traversal sequences blocked with absolute path bypass

**Category:** Directory Traversal
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/file-path-traversal/lab-absolute-path-bypass

Blocking `../` feels like it should end the problem, and a lot of real defenses stop exactly
there. But most languages' path-joining functions have a quirk that makes that defense
incomplete on its own: if the "user-supplied" piece of the path is itself an absolute path,
joining it onto a base directory doesn't extend the base directory at all — it replaces it. A
filter that only watches for traversal sequences never sees that coming, because there isn't one.

## The Target

Same shape as the previous lab in this series — a product image loader at
`GET /image?filename=` — but this time the application has added a defense: it blocks traversal
sequences in the `filename` value before treating it as relative to a default working directory.

## The Investigation

We ran the same generic detector (`detect_traversal`) against this endpoint. Its payload list
tries basic `../` traversal first, and this time that class of payload didn't produce a match —
consistent with the lab blocking traversal sequences outright. The detector moved on to the next
bypass class in its list: absolute paths. If the application's file-lookup code does something
like joining a base directory with the supplied filename, and the supplied filename is already
absolute, most path-join implementations (Python's `os.path.join`, Java's `Paths.resolve`, and
equivalents) discard the base directory entirely and just use the absolute path — meaning the
"blocked traversal sequences" defense was never actually in the way, because this payload
doesn't use one.

## The Exploit

The verified payload:

```
GET /image?filename=/etc/passwd
```

No traversal sequence anywhere in the request. The response still came back containing
`/etc/passwd`'s contents, matched by our confirmation regex, and the lab's home page flipped to
"Congratulations" once the wrapper reloaded it.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution uses the identical payload — intercept the request in Burp and set
`filename` to `/etc/passwd` directly. Same technique, same reasoning: the lab blocks relative
traversal, not absolute paths, and the underlying file-join logic treats an absolute value as a
complete override of the base directory.

The difference worth naming is how we arrived there. PortSwigger's walkthrough tells you the
defense up front (the lab description says traversal sequences are blocked), so the manual
solution goes straight to the absolute-path payload. Our detector didn't have that description —
it worked through basic traversal first, watched it fail silently, and only then reached for the
absolute-path class of payload. That's the actual value of running an ordered list of bypass
classes instead of one hand-picked payload: it doesn't need to be told what the defense is before
it can route around it.

## What This Teaches Us

"Block `../`" is a filter on the *shape* of the input, not on what the input actually does once
it reaches the filesystem API. An absolute path contains no traversal sequence to block, yet it
achieves the identical result — escaping the intended directory — because the vulnerability was
never really about `../` characters. It was about handing untrusted input to a path-join
function and trusting the result to stay inside a boundary that the function itself makes no
guarantee about. The fix from the previous lab still applies unchanged: canonicalize the
resolved path and check it against the base directory *after* resolution, which catches absolute
paths and relative traversal with the same check.
