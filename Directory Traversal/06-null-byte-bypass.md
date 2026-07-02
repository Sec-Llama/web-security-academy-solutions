# File path traversal, validation of file extension with null byte bypass

**Category:** Directory Traversal
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass

Extension allow-listing feels like a strong defense — "the filename has to end in `.png` or
`.jpg`" — right up until the runtime handling the filename and the code validating it disagree
about where the string actually ends. A null byte is where that disagreement lives: older
language runtimes treat `\0` as a hard string terminator at the C level, while the higher-level
validation code checking the extension sees the full string, tail included.

## The Target

The same `GET /image?filename=` image loader, now requiring that the value end in an approved
image extension such as `.png` or `.jpg` before the application will treat it as a valid
filename.

## The Investigation

Basic, absolute, nested, and URL-encoded payloads all failed against this lab, as expected — none
of them end in an approved extension, so the extension check rejects them before traversal is
even a factor. The detector's next class, null-byte payloads, appends a required extension after
an embedded `%00`: a traversal chain to `/etc/passwd`, followed by a literal null byte, followed
by `.png`.

Getting that payload onto the wire correctly needed its own workaround. `httpx`'s standard
`params={}` request builder — the same mechanism that accidentally helped us in the
superfluous-URL-decode lab — percent-encodes the `%` character itself, which would turn our
intended `%00` into the inert three-character string `%2500` instead of an actual null byte. This
time that behavior would have broken the exploit rather than completing it, so `PathTraversal.py`
special-cases it: whenever a payload contains `%00` on a GET request, `read_file` and
`detect_traversal` build the request as a raw URL string (`f"{url}?{param}={payload}"`) instead
of routing it through the params dict, so the null byte reaches the server exactly as written.

## The Exploit

The verified payload:

```
GET /image?filename=../../../etc/passwd%00.png
```

The extension check sees a string ending in `.png` and approves it. The underlying file-open
call, on a runtime where null-byte truncation is still in effect, stops reading the filename at
`%00` and opens `../../../etc/passwd` instead. The response contained the file's contents,
matched by our confirmation regex, and the lab flipped to solved.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution uses the identical payload — `../../../etc/passwd%00.png` — set directly
on the `filename` parameter in Burp Repeater. Burp sends the raw bytes you type without
re-encoding `%00` the way a naive scripted client's dict-based parameter encoder might, so their
path to the same request is more direct than ours needed to be.

The difference worth naming is the one from the previous lab in reverse: there, our HTTP client's
automatic re-encoding of `%` accidentally produced the payload we needed. Here, that same
behavior would have silently destroyed the payload, replacing a real null byte with a harmless
literal string. We had to explicitly detect that case and drop down to building the raw query
string ourselves to avoid it. Two labs in a row where the actual constraint wasn't the traversal
logic at all, but making sure our own tooling put the intended bytes on the wire.

## What This Teaches Us

Null-byte truncation is a runtime-level bug, not a web application logic bug — it's been patched
in modern PHP (5.3.4+) and current JDKs, which is why this technique doesn't work everywhere
anymore. But the underlying lesson generalizes past this specific fix: any validation step that
inspects a string using different termination rules than the component that later *consumes*
that string is a gap, whether the mismatch is a null byte, an encoding layer, or something else
entirely. The fix that closes this lab is the same one this whole series keeps arriving at —
canonicalize the path and validate what it actually resolves to, not properties of the raw input
string, extension included.
