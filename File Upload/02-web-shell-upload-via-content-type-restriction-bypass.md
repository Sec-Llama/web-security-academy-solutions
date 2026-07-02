# Web shell upload via Content-Type restriction bypass

**Category:** File Upload
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-content-type-restriction-bypass

A validation check is only as strong as the thing it actually inspects. This lab's upload function looks like it's doing real filtering — it rejects our PHP shell outright — but the check turns out to be reading a header the client wrote itself, rather than anything about the file's actual content. That's a distinction worth internalizing early in this series: "the server validated the upload" and "the server validated something the attacker didn't control" are not the same claim.

## The Target

Same avatar upload flow as the previous lab: `POST /my-account/avatar` with a multipart file, served back from `/files/avatars/<filename>`. This time the server pushes back on non-image uploads.

## The Investigation

Uploading `exploit.php` with its natural multipart `Content-Type` unmodified was rejected — the response stated only `image/jpeg` or `image/png` files were allowed. That confirmed a Content-Type check existed. The question was what it was actually checking.

The `Content-Type` in a multipart file part is a value the client sets per-part in the request body — it's metadata attached by whoever built the request, not something the server derives by inspecting the bytes. If the server's validation logic just reads that field and trusts it, then the file's real content is irrelevant to whether the check passes.

## The Exploit

We kept the file content and filename identical — still `exploit.php` containing the same secret-reading PHP one-liner — and only changed the declared MIME type of that multipart part to `image/jpeg`:

```
POST /my-account/avatar
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
Content-Type: image/jpeg

<?php echo file_get_contents('/home/carlos/secret'); ?>
```

The server accepted the upload — the same PHP payload that was rejected moments earlier now passed, because nothing about the check touched the actual bytes. Fetching `GET /files/avatars/exploit.php` executed the script and returned Carlos's secret in the response body, which we submitted to solve the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the same conclusion via the same mechanism: after the initial upload attempt is rejected for having the wrong MIME type, they replay the `POST /my-account/avatar` request in Burp Repeater and edit the file part's `Content-Type` header from whatever PHP declares by default to `image/jpeg`, leaving the filename and PHP content untouched. That's exactly the bypass we used.

The only difference is tooling: PortSwigger edits the header by hand in Repeater's raw request view, we set it directly as the third element of the file tuple in an `httpx` multipart upload (`files = {"avatar": (filename, content, "image/jpeg")}`). Same header, same value, same result — a scripted request and a hand-edited one are indistinguishable to the server once they're on the wire.

## What This Teaches Us

Content-Type headers are exactly as trustworthy as any other client-supplied input, which is to say not at all on their own. A validation routine that reads `request.files['avatar'].content_type` and branches on it is checking a claim, not a fact — the actual bytes behind that claim were never inspected. The fix that later labs in this series push toward is validating what the file actually is: magic bytes, parseable image structure, or ideally re-encoding the upload through a trusted image library rather than trusting any metadata the request itself asserts about its own contents.
