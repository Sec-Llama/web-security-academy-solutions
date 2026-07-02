# JWT authentication bypass via kid header path traversal

**Category:** JWT
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal

The `kid` (key ID) header parameter is meant to tell the server which of its own trusted keys to
use for verification — useful when multiple keys are in rotation. Some implementations resolve
that ID by reading a file from disk whose path is built directly from the `kid` value. Whenever a
filesystem path gets built from user-controlled input, path traversal is the obvious question to
ask, and this lab answers it: if `kid` can walk the path outside the intended keys directory, it
can be pointed at any file on the system — including files with entirely predictable contents.

## The Target

Same session-cookie-gates-`/admin` structure as the rest of this set. Here the server resolves its
HS256 verification key by reading a file named after the token's `kid` header field, with no
apparent sanitization against traversal sequences.

## The Investigation

If `kid` becomes part of a file read on disk, the natural target is a file whose contents are known
and constant — and `/dev/null` is exactly that: it always reads back as zero bytes on any Unix-like
system. If the server takes those zero bytes and uses them directly as the HMAC secret, then
signing with an empty-string secret produces a signature the server will accept, because it's
computing the exact same thing on its side when it reads the same empty file.

We set `kid` to a traversal sequence reaching back to `/dev/null` from wherever the server's keys
directory lives, padding with enough `../` segments to clear any reasonable directory depth, and
set the algorithm to `HS256`:

```python
def exploit_forge_kid_traversal(jwt_token: str, new_claims: dict,
                                 kid_path: str = "../../../dev/null",
                                 secret: str = "") -> str:
    header, payload, _ = decode_jwt(jwt_token)
    payload.update(new_claims)
    header["kid"] = kid_path
    header["alg"] = "HS256"
    return encode_jwt(header, payload, secret.encode(), "HS256")
```

## The Exploit

With `kid` set to `../../../dev/null`, `sub` set to `administrator`, and the token signed with an
empty-string HMAC secret, the forged token's signature matched what the server computed after
reading `/dev/null` as its key material. Setting it as the session cookie and requesting `/admin`
succeeded, and the delete request against `carlos` solved the lab. Our tooling also documents
`/dev/zero` and `/proc/sys/kernel/hostname` as alternate traversal targets worth trying if
`/dev/null` isn't reachable from a given server's working directory.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution uses Burp's JWT Editor extension: create a new symmetric key in the Keys
tab and replace its `k` property with an empty string, then in the `GET /admin` request's JSON Web
Token editor, set `kid` to `../../../../../../../dev/null`, set `sub` to `administrator`, and sign
with the empty-secret symmetric key before sending — noting their traversal string uses more `../`
segments than ours (seven versus three), reflecting a deeper assumed keys-directory nesting; both
work because path traversal sequences are simply collapsed by the filesystem regardless of how many
extra `../` segments are present once the traversal has already escaped past the root.

The technique — traverse to `/dev/null`, sign with an empty secret — is identical between the two
approaches. The difference is again tooling: Burp's JWT Editor extension manages the symmetric key
and signing through its GUI, while our `exploit_forge_kid_traversal()` function builds and signs
the token directly with Python's `hmac` module against an empty-bytes secret.

## What This Teaches Us

This lab is a reminder that header parameters meant purely as *lookup identifiers* — `kid` is
supposed to just select among a fixed set of known-good keys — become dangerous the moment the
lookup mechanism trusts the identifier's literal value without validating it against an expected
format or a fixed allow-list. The same class of bug shows up whenever a filename, a database key,
or a cache key gets built from unsanitized user input; JWT `kid` handling is just one specific,
well-known surface for it. The fix is to resolve `kid` against a strict allow-list of known key
identifiers — reject anything that isn't an exact match — rather than treating it as a path
fragment or a query parameter to be interpolated directly into a lookup.
