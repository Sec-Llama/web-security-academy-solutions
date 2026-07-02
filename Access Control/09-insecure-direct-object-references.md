# Lab: Insecure direct object references

**Category:** Access Control
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references

Not every IDOR lives in a URL query parameter pointing at a database row. Static files — transcripts,
exports, generated documents — are direct object references too, and they're easy to overlook
precisely because they don't look like "the application"; they look like a file the server happens
to be serving.

## The Target

The site has a live chat feature. Sending a message and requesting a transcript returns a
downloadable text file at a URL like `/download-transcript/<N>.txt`, where `N` is an incrementing
number the server assigns per transcript.

## The Exploit

Sequential, predictable filenames on a resource with no ownership check attached is exactly the
IDOR pattern from the earlier labs, just applied to static files instead of dynamic pages. We didn't
need to generate our own transcript first — if the numbering is global and incrementing, earlier,
lower-numbered transcripts belong to other users (or the site's own seeded conversations) and should
already exist on disk. We swept the low end of the range directly:

```python
for i in range(1, 10):
    url = f"{base}/download-transcript/{i}.txt"
    resp = client.get(url)
    if _is_success(resp) and len(resp.text) > 10:
        ...
```

```
/download-transcript/1.txt    -- Increment file number
POST /download-transcript -> redirects to /download-transcript/N.txt  -- Server assigns sequential filenames
regex: password\s+is\s+(\S+)  -- Extract password from chat transcript
```

`/download-transcript/1.txt` returned a real transcript — a conversation containing a password in
plain text. A regex matching `password is <value>` against the transcript body pulled the credential
out directly.

## Login and Solve

With the recovered password in hand, we authenticated as `carlos` (the account referenced in the
leaked transcript) and confirmed the login succeeded, which solved the lab:

```python
_login(client, base, "carlos", password)
```

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution starts from the live chat feature itself: send a message, view the resulting
transcript, notice the URL pattern with an incrementing filename, change it down to `1.txt`, find a
password inside, and log in with the stolen credentials.

We took a shortcut relative to that path. Rather than sending a chat message first to learn the URL
pattern from a transcript we generated ourselves, we already knew the endpoint shape —
`/download-transcript/<N>.txt` — from the vulnerability class itself, and went straight to sweeping
low numbers without ever using the live chat feature. Both approaches converge on the same
`1.txt` file and the same leaked password; the difference is that PortSwigger's walkthrough uses the
chat feature to *discover* the URL pattern, while our script assumed the pattern and verified it by
requesting the file directly. On a real target, discovering the pattern first (as the official
solution does) would be the safer general approach — assuming a pattern only works when it's this
predictable.

## What This Teaches Us

A file server that hands out sequential filenames is leaking an enumerable index into every resource
it's ever served, transcript-shaped or not. The access control failure here is identical in kind to
the parameter-based IDORs earlier in this series — no check that the requester owns the resource
being requested — but it's worth calling out separately because static file serving often sits
outside the same code path (and the same security review) as the application's dynamic routes.
Anywhere a server generates a resource with a predictable name and serves it without an ownership
check, it's the same bug wearing a file extension.
