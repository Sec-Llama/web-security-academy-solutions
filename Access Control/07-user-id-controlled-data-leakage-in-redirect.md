# Lab: User ID controlled by request parameter with data leakage in redirect

**Category:** Access Control
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect

Redirecting an unauthorized request away from sensitive data looks like an access control fix on
the surface — the browser never renders the page it wasn't supposed to see. But a redirect is just
an HTTP response with a `3xx` status and a `Location` header; nothing stops the server from also
writing a response *body* to that same response, and nothing stops an HTTP client from reading it
before following the redirect.

## The Target

The account page pattern is identical to the earlier IDOR labs — `/my-account?id=<username>` — with
one behavioral difference: requesting another user's `id` now returns a redirect back to the
homepage instead of rendering the page directly. On its own, that looks like the access control gap
from Lab 5 has been closed.

## The Investigation

The fix, if it is one, only matters if the redirect response is empty. We configured our HTTP
client to stop following redirects automatically so we could inspect exactly what the server sent
back before any redirect was acted on:

```
follow_redirects=False, read 302 body    -- Data leaks in redirect body
-- Key: httpx Client(follow_redirects=False) to read body of 302
```

```python
with _client(allow_redirects=False) as client:
```

With redirects no longer followed transparently, the raw response to the IDOR request became
readable — including whatever body accompanied that `3xx` status.

## The Exploit

Logged in as `wiener` (manually following just the login redirect, since we needed the session
cookie without losing visibility into the next response), we requested `carlos`'s account:

```python
resp = client.get(f"{base}/my-account", params={"id": "carlos"})
```

The response came back as a redirect to the homepage, exactly as expected — but the body attached to
that redirect still contained the full account page markup, API key included. We extracted it with
the same regex used in the earlier IDOR labs, then submitted it through a second client (one that
does follow redirects normally, since the solution endpoint doesn't need the same inspection). The
lab solved on submission.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution is the same observation: change the `id` parameter to `carlos` in Burp
Repeater, notice the response is a redirect to the home page, but that the response still has a body
containing `carlos`'s API key, then submit it. The core insight — that the redirect's body was never
actually emptied — is identical to what we found.

The mechanical difference is how each of us kept that body from being discarded. Burp Repeater
shows the raw response regardless of status code, so a human never loses sight of the body just
because it's attached to a `3xx`. Our `httpx` client would have followed the redirect and thrown the
intermediate response away by default, which is why disabling `follow_redirects` was the specific
step that mattered here — without it, the leaking body would have been invisible to the script even
though the vulnerability was still present.

## What This Teaches Us

Whoever patched this endpoint fixed the symptom a browser shows a user — no page renders, so it
*looks* protected — without fixing the underlying cause, which is that the server still builds the
full response for an unauthorized request before deciding to redirect. Real access control has to
happen before any sensitive data is written to the response, not after, and it has to be verified by
inspecting the raw bytes on the wire rather than trusting that "redirects away" means "data withheld."
