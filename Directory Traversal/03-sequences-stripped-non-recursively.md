# File path traversal, traversal sequences stripped non-recursively

**Category:** Directory Traversal
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/file-path-traversal/lab-sequences-stripped-non-recursively

A string-replace defense that removes `../` sounds reasonable until you ask a simple question:
does it check the result of the replacement, or does it just run once and trust the output? This
lab targets a filter that strips the sequence exactly one time — which means the forbidden
pattern can be hidden inside itself, so that stripping it once leaves the very thing it was
supposed to remove.

## The Target

The same `GET /image?filename=` product-image loader, now defended by a filter that strips `../`
sequences from the input — but only in a single pass, not recursively.

## The Investigation

Our detector worked down its payload list again. Basic `../` traversal failed, as expected —
the filter strips exactly that sequence. The absolute-path payloads also failed, meaning this
lab (unlike the previous one) doesn't have the same base-directory-override quirk in play. The
next class in the list, "nested" traversal, was built for precisely this defense: strings like
`....//` that contain `../` as a substring once you look past the extra characters. When a
single-pass strip removes the embedded `../` from inside `....//`, what's left over is `../` —
the filter, by doing its job exactly once, hands the attacker back the sequence it just deleted.

## The Exploit

The verified payload:

```
GET /image?filename=....//....//....//etc/passwd
```

Each `....//` segment collapses to `../` after the filter's single pass, reassembling into a
working traversal chain by the time the file lookup runs. The response contained `/etc/passwd`,
matched by our confirmation regex, and the lab flipped to solved.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution uses the exact same payload: `....//....//....//etc/passwd`, entered
directly into the `filename` parameter through Burp. This is a clean match, both in payload and
in reasoning — there's really only one way to defeat a single-pass strip of a fixed-length
token, which is to embed the token inside a longer string that still contains it as a substring.

As with the earlier labs in this series, the only procedural difference is that our detector
reached this payload automatically, by ruling out basic and absolute-path payloads first rather
than being told upfront that the filter strips non-recursively.

## What This Teaches Us

This is the first lab in the series where the defense actually engaged with the input and still
lost, because it stopped one step too early. Removing a forbidden substring is not the same as
removing every path to that substring existing after removal — the two operations only coincide
if the strip is applied repeatedly until the string stops changing, or if the validation happens
on the final resolved path rather than on an intermediate, partially-cleaned string. Every
correct fix in this series routes through the same idea: stop trying to sanitize the input
string and instead canonicalize the path and check the *result*, which makes the number of
passes over the raw string irrelevant.
