# Remote code execution via web shell upload

**Category:** File Upload
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload

File upload functionality turns a web server into something that will happily write attacker-controlled bytes to disk. Whether that becomes remote code execution comes down to a single question: does anything stand between "user selected a file" and "server stored it somewhere it will execute"? This lab is the baseline case — the answer is nothing at all — and it's the reference point every other lab in this series bypasses its way back to.

## The Target

The application is a blog site with a user account page that lets a logged-in user set an avatar image. A normal upload is a `POST /my-account/avatar` multipart request carrying the image bytes, and the resulting file becomes reachable at `GET /files/avatars/<filename>`.

## The Investigation

We logged in as `wiener`/`peter` and looked at what the avatar upload accepted. There was no client-side or server-side check on file type, extension, or content — the endpoint stored whatever filename and bytes it was given and served them back verbatim from `/files/avatars/`. That's the whole vulnerability: if the upload directory also has PHP execution enabled, uploading a `.php` file is indistinguishable from uploading a `.jpg` as far as the server's validation logic is concerned.

We wrote a minimal PHP web shell that reads the target file the lab uses as its solve condition:

```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

## The Exploit

We uploaded that file directly as `exploit.php` through the avatar form, with no bypass needed:

```
POST /my-account/avatar
Content-Disposition: form-data; name="avatar"; filename="exploit.php"

<?php echo file_get_contents('/home/carlos/secret'); ?>
```

The server accepted it and confirmed the upload. Requesting the file back triggered execution instead of returning source:

```
GET /files/avatars/exploit.php
```

The response body was the contents of `/home/carlos/secret` — plain text, no PHP tags, no error — proof the server had executed our uploaded script. We submitted that value through the lab's solve form and the lab flipped to solved.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's published solution follows the same shape: log in, upload an image to observe the `/files/avatars/<file>` URL pattern via Burp's proxy history, then create `exploit.php` with the identical `file_get_contents('/home/carlos/secret')` one-liner, upload it through the avatar form, and replace the filename in a Repeater tab with `exploit.php` to trigger execution.

There's no technique divergence here — this is the one lab in the series where nothing needs to be bypassed, so the official walkthrough and our approach land on the exact same request. The only difference is delivery: PortSwigger drives it by hand through Burp's Proxy/Repeater tabs, we sent the same two requests (upload, then fetch) directly through a Python script. For a lab with zero validation to defeat, both paths are just "send the request" — the gap between manual and scripted only starts to matter once there's a bypass technique to iterate on.

## What This Teaches Us

The vulnerability isn't a clever bypass — it's the absence of any check at all. Extension filtering, content-type validation, and content inspection all exist specifically to prevent this exact scenario, and every subsequent lab in this series is really testing whether one particular layer of that defense can be defeated. The fix is the same one that applies everywhere in this category: never let the upload directory execute code, regardless of what's in it. Serving uploaded files from a location with script execution disabled (or from a separate domain/storage service entirely) makes the question of "did we validate the file correctly" moot, because even a successfully uploaded web shell has nowhere to run.
