# File path traversal, validation of start of path

**Category:** Directory Traversal
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/file-path-traversal/lab-validate-start-of-path

Checking that a path "starts with" the expected directory sounds like a reasonable guard, but a
prefix check is a check on the string, not on where the path actually resolves to. If the
validation runs before the traversal sequences are resolved, satisfying the prefix costs nothing
— you just put the required prefix at the front and walk back out from there.

## The Target

The same `GET /image?filename=` image loader, now requiring that the supplied path begin with
the application's expected image directory before it will serve anything.

## The Investigation

This lab needed one extra piece of information the earlier labs didn't: the expected base
directory string itself. Rather than hardcoding it, our detector's `_infer_base_dir` helper
reads the `filename` parameter's own baseline value — if it's already an absolute path (which a
normal, unmodified image request for this lab is), it extracts the directory portion
automatically. For a request like `?filename=/var/www/images/34.jpg`, that yields
`/var/www/images` without us needing to have manually inspected the lab first.

With that base directory known, the detector appends a start-of-path payload class to its list:
the inferred base directory followed by a traversal chain back out to `/etc/passwd`. Basic,
absolute, nested, and URL-encoded payloads all failed first, as expected — this lab's defense is
specifically the prefix check, and none of those payload classes satisfy it. The start-of-path
payload does, because it opens with exactly the string the validation is looking for.

## The Exploit

The verified payload:

```
GET /image?filename=/var/www/images/../../../etc/passwd
```

The string starts with `/var/www/images`, satisfying the prefix check, and the trailing
`../../../etc/passwd` walks back out past it once the path is actually resolved on disk. The
response contained `/etc/passwd`, matched by our confirmation regex, and the lab flipped to
solved.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the identical payload —
`/var/www/images/../../../etc/passwd` — set on the `filename` parameter through Burp.

The interesting difference here is how each side learns the base directory. PortSwigger's manual
walkthrough gets it from context: you'd notice `/var/www/images/34.jpg` or similar in a normal
request while exploring the lab, and reuse that observed prefix by hand. Our tool doesn't rely on
an operator noticing anything — `_infer_base_dir` extracts the same prefix programmatically from
whatever value the parameter already holds, which means the same detector generalizes to any
target using this pattern without needing to be told the base directory up front.

## What This Teaches Us

A prefix check on a string is only as strong as the assumption that the string can't grow a `..`
tail after the prefix and still be trusted. Because `/var/www/images/../../../etc/passwd`
genuinely does start with `/var/www/images`, the check itself never fails — it's satisfied
completely and correctly, right before the filesystem resolves the rest of the string and walks
straight past the boundary the check thought it was enforcing. This is the clearest illustration
in the series of why "validate the canonical, resolved path" and "validate the raw input string"
are not interchangeable: the same string can pass a startswith check and still resolve somewhere
that check was never meant to allow.
