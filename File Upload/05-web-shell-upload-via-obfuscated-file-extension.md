# Web shell upload via obfuscated file extension

**Category:** File Upload
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-obfuscated-file-extension

Whitelisting extensions closes off the gap the previous lab exploited, but a whitelist check is still just string comparison — and string comparison inherits every quirk of however the underlying language handles strings. This lab targets one of the oldest of those quirks: null-byte termination, a leftover behavior from C-style string handling that PHP's own string functions were built on top of for years.

## The Target

The avatar upload endpoint, now restricted to a strict whitelist: only `.jpg` and `.png` extensions are accepted, confirmed by uploading `exploit.php` directly and receiving an explicit rejection.

## The Investigation

With a whitelist in place, appending a real image extension anywhere in the filename was the obvious direction — the question was whether the check happened against the full filename string or against something the filesystem layer would truncate differently. A `%00` (null byte) is a legacy string terminator in C, and PHP's file-handling functions historically inherited that behavior: a function scanning a string for its extension might read all the way to the true end of the string, see `.jpg`, and approve it — while the underlying OS call that actually writes the file to disk stops reading at the null byte and saves everything before it.

## The Exploit

We named the file so that the extension-check would see `.jpg` while the save operation would see only `exploit.php`:

```
Content-Disposition: form-data; name="avatar"; filename="exploit.php%00.jpg"
Content-Type: application/x-php

<?php echo file_get_contents('/home/carlos/secret'); ?>
```

The server accepted the upload — and notably, its own confirmation message referred to the saved file as `exploit.php`, confirming the null byte had done exactly what we expected: truncated the string at save time, discarding `%00.jpg` entirely. Fetching the file by its real, truncated name executed it:

```
GET /files/avatars/exploit.php
```

The response returned Carlos's secret, which we submitted to solve the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches this via the same reasoning: after confirming the JPG/PNG whitelist, they replay the upload request in Repeater and set the filename to `exploit.php%00.jpg` — a URL-encoded null byte followed by the whitelisted extension. Their walkthrough calls out the same tell we noticed: the server's success message names the file `exploit.php`, not `exploit.php%00.jpg`, which is the confirmation that the null byte truncated the name before it hit disk.

The mechanism is identical between their approach and ours; only the delivery differs, Repeater edit versus a Python multipart request carrying the same encoded filename.

## What This Teaches Us

This bug exists because two different layers of the same application — the validation logic and the filesystem write — disagreed about where a string ends. The whitelist check trusted `str.endswith('.jpg')` or equivalent against the full filename, but `move_uploaded_file()` (or whatever eventually persisted the bytes) used a lower-level, null-terminated string convention underneath. Treating "does this filename look safe" and "what will actually be written to disk" as the same question is the root mistake; the fix is to never derive the on-disk filename from user input at all — generate it server-side, and use the original name only for cosmetic purposes like a download prompt.
