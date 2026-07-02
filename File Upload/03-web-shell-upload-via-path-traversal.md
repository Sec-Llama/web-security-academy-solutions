# Web shell upload via path traversal

**Category:** File Upload
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-path-traversal

Some applications solve "don't let uploaded files execute" by putting the upload directory somewhere script execution is disabled. That's a reasonable control right up until the filename itself becomes an attack surface — because a filename isn't just a label, it's a path, and if the server builds a filesystem path by concatenating a directory with unsanitized user input, the upload can land somewhere the developer never intended.

## The Target

The familiar avatar upload endpoint, but this time `/files/avatars/` is explicitly configured not to execute PHP — uploading and requesting `exploit.php` there just returns the raw source as plain text, no bypass required to get the file stored, but no execution either.

## The Investigation

Uploading `exploit.php` with no obfuscation worked without any pushback — the server clearly wasn't filtering PHP by extension here. Fetching it back, though, returned the literal PHP source rather than executed output, which told us the *directory* was the control, not the upload itself. That reframed the problem: we didn't need a new bypass technique, we needed to make the file land in a different directory — specifically `/files`, one level up from `/files/avatars/`, which our recon showed did have execution enabled.

The filename in a multipart `Content-Disposition` header is exactly that: a string the server presumably uses to construct a save path. A plain `../` traversal sequence in that filename was our first attempt:

```
Content-Disposition: form-data; name="avatar"; filename="../exploit.php"
```

That got stripped — the response reported the file saved as `avatars/exploit.php`, meaning the server sanitized `../` sequences before writing to disk. The next question was *when* that sanitization ran relative to any URL-decoding step.

## The Exploit

We URL-encoded the forward slash in the traversal sequence, so the literal bytes in the filename field no longer matched whatever pattern the server's `../` filter was looking for:

```
Content-Disposition: form-data; name="avatar"; filename="..%2Fexploit.php"
```

The server accepted it and reported the upload succeeded — meaning the traversal-stripping check ran against the raw `..%2F` string, saw no literal `../`, and let it through. Only afterward did the server URL-decode the filename into `../exploit.php` when actually saving it, placing the file in `/files/exploit.php` instead of `/files/avatars/exploit.php`. Requesting it there executed the script:

```
GET /files/exploit.php
```

The response returned Carlos's secret in plaintext, confirming both the traversal and the execution. We submitted the recovered value to solve the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the identical two-stage logic: first confirm plain `../` gets stripped (their walkthrough notes the response says `The file avatars/exploit.php has been uploaded`, proving the sanitizer ran but the file wasn't blocked outright), then bypass it with the same URL-encoded slash, `filename="..%2fexploit.php"`. They also point out the resulting file is reachable at both `/files/avatars/..%2fexploit.php` (via the encoded path) and the simpler `/files/exploit.php` — the same two access paths our fetch confirmed.

The technique is exactly the same; the only difference is that PortSwigger edits the `Content-Disposition` header by hand across two Burp Repeater tabs (one for the upload, one for the fetch), while we built both requests directly with a Python multipart upload and a follow-up GET. The order-of-operations bug — sanitize first, decode second — is what makes the encoded-slash bypass work regardless of which client sends the bytes.

## What This Teaches Us

This lab is a clean illustration of a filter running at the wrong stage of the pipeline. Stripping `../` is a reasonable idea, but stripping it *before* decoding the input means the filter is checking a string that hasn't taken its final form yet — anything the decoder later reconstructs into a traversal sequence sails through untouched. The durable fix isn't a smarter blacklist; it's not trusting the client-supplied filename for the storage path at all. Generating a random server-side filename (and storing the original name only as metadata, if needed for display) removes the traversal surface entirely, independent of directory execution settings.
