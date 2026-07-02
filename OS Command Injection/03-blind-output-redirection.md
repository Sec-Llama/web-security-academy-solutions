# Blind OS command injection with output redirection

**Category:** OS Command Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection

Time-based confirmation proves a command ran, but it doesn't tell you what that command actually
returned — for that you need the output somewhere you can read it. If the compromised process can
write to a directory the web server also serves as static files, the shell itself becomes the data
channel: redirect the command's output into that directory, then simply request the file over
HTTP.

## The Target

The same feedback form as the previous lab:

```
POST /feedback/submit
csrf=...&name=test&email=test@test.com&subject=test&message=test
```

but this store also serves product images from a predictable, web-accessible path —
`/var/www/images/` — fetched through:

```
GET /image?filename=<name>
```

A writable directory that's also a servable one is exactly the combination this technique needs:
write the command's output as a file inside it, then read that file back out over plain HTTP.

## The Investigation

We already knew from the previous lab that the feedback form's fields reach a shell asynchronously
with no output in the response. The question here was narrower: could we redirect that command's
stdout into `/var/www/images/`, and would the image-loading endpoint serve back a file that isn't
actually an image.

We targeted the `email` parameter specifically — the same one confirmed injectable in the previous
lab — and built the command as a redirect rather than a canary: `whoami > /var/www/images/output.txt`.
The OR-chain operator (`||`) was the first one we tried, and it worked directly, without needing to
fall back to any of the other operators in the list.

## The Exploit

The submission that wrote the output file:

```
email=||whoami>/var/www/images/output.txt||
```

Followed by fetching it:

```
GET /image?filename=output.txt
```

The first request causes the backend to run `whoami` and redirect its stdout into a file inside the
already-web-accessible images directory. The second request asks the image endpoint for that exact
filename — the endpoint doesn't validate that the requested file is actually an image, it just
serves whatever's at that path, and the response body was the raw text output of the `whoami`
command: the identity of the user the web server process runs as, recovered without a single byte
of that output ever touching the feedback form's own HTTP response.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's published solution uses the identical two-step flow: intercept the feedback
submission and set `email=||whoami>/var/www/images/output.txt||`, then intercept the product image
request and change its `filename` parameter to `output.txt` to retrieve the result. This matches
what we did exactly, payload for payload — the OR-chain redirect construction we tried first is the
same one PortSwigger's walkthrough uses, not a fallback we had to search for.

The only difference is delivery: PortSwigger edits both requests by hand through Burp's proxy, we
sent them as two direct scripted requests. For a technique this deterministic — one redirect, one
fetch, no character-by-character extraction — manual and scripted approaches really do converge on
the exact same two HTTP requests.

## What This Teaches Us

This lab generalizes a principle worth remembering beyond command injection specifically: any time
an attacker can both write to a location and separately read from that same location through a
different feature, those two capabilities compose into a data channel neither one provides on its
own. The redirection itself required nothing exotic — shell output redirection is about as basic as
shell syntax gets — the interesting part is recognizing that a "product image loader" and a "shell
command" share a filesystem, and that sharing is the actual vulnerability surface. The underlying
fix is unchanged from the previous labs: never let user input reach a shell as an interpreted
string. But hardening the file-serving side would also have closed this off independently — an
image endpoint that validates file type and restricts its search path can't be repurposed as an
arbitrary-file reader, redirect or no redirect.
