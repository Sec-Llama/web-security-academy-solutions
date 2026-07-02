# JWT authentication bypass via unverified signature

**Category:** JWT
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature

A JWT's whole security model rests on one assumption: the server actually checks the signature
before trusting anything inside the token. That sounds too basic a thing to get wrong, but the
distinction between "parse this JWT" and "verify this JWT" is a single function call in most
libraries, and mixing them up is a mistake that's shown up in real authentication systems, not
just training labs. This lab is the cleanest possible demonstration of what happens when a server
makes exactly that mistake.

## The Target

The lab is a web app that authenticates users with a session cookie in JWT format —
`header.payload.signature`, Base64url-encoded and dot-separated. Logging in as a normal user
returns a token whose payload carries a `sub` claim identifying the account. An `/admin` panel
exists behind this same session cookie, restricted to the `administrator` user, with a
`/admin/delete?username=carlos` action reachable from it.

## The Investigation

Decoding the session JWT's payload shows a structure like:

```json
{"sub":"wiener","iat":1234567890}
```

with an RS256 header. The question worth testing before anything more advanced: does the server
actually recompute and check that signature, or does it just decode the payload's JSON and trust
whatever claims are inside it? We tested this directly — take the token apart, edit the `sub`
claim, and put it back together *without* generating a new valid signature, keeping the original
signature bytes as-is. If the server calls something equivalent to `jwt.decode()` instead of
`jwt.verify()`, the tampered token gets accepted because nothing ever re-checks that the signature
actually matches the new payload.

## The Exploit

We logged in normally to obtain a genuine session JWT, then forged a new token that kept the
original header and original (now-invalid) signature but changed the payload's `sub` claim from
`wiener` to `administrator`:

```python
def exploit_forge_unverified(jwt_token: str, new_claims: dict) -> str:
    header, payload, sig = decode_jwt(jwt_token)
    payload.update(new_claims)
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{sig}"
```

Setting that forged token as the session cookie and requesting `/admin` returned the admin panel —
proof the signature was never actually checked. From there, the panel exposed the delete link for
`carlos`, and calling `/admin/delete?username=carlos` with the forged cookie still attached solved
the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's published solution reaches the same result through Burp: log in, capture the
post-login `GET /my-account` request in Proxy history, send it to Repeater, change the path to
`/admin`, then use the JWT Inspector panel to edit the `sub` claim from `wiener` to `administrator`
and click Apply — which, notably, does not touch the signature at all. Sending that request
succeeds, and the response contains the delete link for `carlos`.

The technique is identical — the vulnerability is "signature isn't checked," so nothing needs to
be signed correctly in either approach. The only real difference is delivery: PortSwigger edits
the token by hand in Burp's Inspector GUI and forwards it; we built the forged token with a small
Python helper that decodes, edits the payload, and reassembles the token with the original
signature untouched, then sent it directly with `httpx`.

## What This Teaches Us

This lab is a reminder that a JWT's cryptographic signature only provides security if something on
the server side is actually validating it against the current payload on every request. A token
that merely *looks* like a JWT — three Base64url segments separated by dots — carries zero
integrity guarantee on its own; the guarantee comes entirely from the verification step. Any
library that offers both a "decode" and a "verify" function is one accidental substitution away
from this exact bug. The fix is just as simple as the flaw: every request handler that trusts
claims from a JWT must call the library's actual signature-verification function, not just parse
the payload.
