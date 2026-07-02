# Lab: Modifying serialized objects

**Category:** Insecure Deserialization
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-objects

Deserialization bugs are unusual among web vulnerabilities because the attack surface isn't a
parameter or a query — it's a data format that the application trusts implicitly. This lab is
the simplest possible demonstration of that trust being misplaced: an access-control flag lives
inside a serialized object, and that object is sitting in plain sight, base64-encoded, in the
session cookie every request carries.

## The Target

The lab is a small storefront with a login flow. After authenticating, the post-login
`GET /my-account` request carries a session cookie that is base64-encoded. Decoding it doesn't
reveal a JWT or an opaque token — it reveals a PHP serialized object, the actual in-memory
representation of a `User`, shipped straight to the client and trusted on the way back.

## The Investigation

PHP's native serialization format is self-describing: `O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:1;}`
tells you the class name, the property count, and each property's type and value inline. That
transparency is exactly the problem — once we decoded the cookie, the `admin` attribute was
sitting there as `b:0`, a plain boolean `false`, with nothing protecting it beyond the fact that
an ordinary user wouldn't think to look. There's no signature, no MAC, no server-side session
store being consulted; the object the client presents *is* the authorization state.

## The Exploit

We took the verified payload template for this lab — the same `User` object with the `admin`
flag flipped:

```
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:1;}
```

Base64-encoded and sent back as the session cookie, this turns a normal user into an
administrator with no further validation. Requesting `/my-account` with the modified cookie
returned a response containing a link to `/admin` — confirmation that the server had deserialized
our tampered object and granted admin privileges based solely on the `b:1` we'd written in. From
there, `/admin` exposed a delete-user action, and a request to
`/admin/delete?username=carlos` removed the target account and solved the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's published solution reaches the same outcome through the same core edit — flip the
`admin` attribute from `b:0` to `b:1` in the serialized cookie — but drives it through Burp
Suite's Inspector panel: intercept the `/my-account` request, let Inspector parse the cookie into
its structured PHP-object view, change the `admin` value in that GUI, click "Apply changes" (which
re-serializes and re-encodes automatically), then pivot the request path to `/admin` and finally
to `/admin/delete?username=carlos`.

The technique is identical; the delivery differs. We built the tampered serialized string
directly and sent it as a cookie header via script, which is really the same edit Inspector makes
for you, just done by hand instead of through a GUI diff. For a single-attribute flip like this
one, both paths converge on the exact same bytes on the wire.

## What This Teaches Us

The vulnerability here isn't really about PHP serialization syntax — it's about where trust
boundaries actually sit. The `admin` flag was meant to be server-controlled state, but because
the object carrying it round-trips through the client unauthenticated and unsigned, the client
became the authority over its own privilege level. Any serialization format exhibits this same
flaw if the server deserializes client-supplied data without a MAC or signature over it: JSON web
tokens solve this with a signature; this cookie solved it with nothing at all. The fix isn't
"don't use PHP serialization" — it's "never let the client be the sole custodian of security-
relevant state," whether that state is base64 PHP objects, JSON, or anything else the browser can
edit before sending it back.
