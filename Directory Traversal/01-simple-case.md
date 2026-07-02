# File path traversal, simple case

**Category:** Directory Traversal
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/file-path-traversal/lab-simple

Path traversal is one of the oldest vulnerability classes in web security, and also one of the
most literal: the bug is right there in the name. An application takes a filename from the user,
concatenates it onto a base directory, and hands the result straight to the filesystem. No
canonicalization, no prefix check, nothing standing between a user-supplied string and an
arbitrary read anywhere the server process can see. This lab is that bug with zero defenses in
front of it, which makes it the right place to start a series on the technique — every later lab
in this set is really just "the same idea, plus one obstacle."

## The Target

The lab is a storefront that loads product images through a dedicated endpoint:

```
GET /image?filename=example.jpg
```

The `filename` value picks which file gets served back as the image response. Nothing about the
request suggests it's doing anything more sophisticated than looking up a name inside a fixed
images directory.

## The Investigation

We pointed our generic path traversal tool, `PathTraversal.py`, at the endpoint. Rather than
guessing a single payload by hand, the tool's Layer 1 detector (`detect_traversal`) works through
an ordered list of traversal payloads covering several bypass classes — basic `../` sequences,
absolute paths, non-recursively-stripped nesting, URL-encoded and double-URL-encoded sequences,
and null-byte extension tricks — and stops at the first response whose body matches
`root:.*:0:0:`, the signature of a real `/etc/passwd` file.

Against this lab, the very first entry in that list was enough. The basic traversal payload —
six levels of `../` prepended to `etc/passwd` — came back on the first try, meaning the
`filename` parameter was being concatenated directly into a file path with no filtering
whatsoever.

## The Exploit

The confirmed, verified payload:

```
GET /image?filename=../../../etc/passwd
```

The response body contained the contents of `/etc/passwd`, matched by our confirmation regex
against the `root:` line every Unix passwd file starts with. The lab wrapper then reloaded the
lab's home page and checked for the "Congratulations" banner PortSwigger displays once a lab is
solved — it appeared, confirming the read wasn't just successful but also recognized as the
intended solve condition.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's published solution reaches the same payload: intercept the image request in Burp
Suite and change `filename` to `../../../etc/passwd`. There's no technique divergence here —
this lab has no defenses to route around, so there's only one payload that makes sense.

The only real difference is delivery. PortSwigger's walkthrough is a manual Burp Repeater edit.
Ours came out of a generic detector that didn't know in advance this lab had no filtering at
all — it simply tried the most basic traversal payload first, in a list that also contains
payloads for five other defenses, and got a hit immediately. For this lab that's overkill; the
same detector earns its keep on the labs that follow, where the basic payload gets blocked and
the tool has to fall through to something else.

## What This Teaches Us

The vulnerability here isn't really about the `../` sequence — it's about trusting a
user-supplied string to become part of a filesystem path with no validation at any point in the
chain. The fix is the same regardless of how elaborate the bypass techniques in later labs get:
resolve the requested path to its canonical, absolute form and verify it still starts with the
intended base directory before opening it. Anything short of that canonicalization step — string
matching, blocklisting `../`, or trusting the input's shape — is a filter waiting for the right
bypass, which is exactly what the rest of this series goes on to demonstrate.
