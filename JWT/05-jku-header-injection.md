# JWT authentication bypass via jku header injection

**Category:** JWT
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection

Instead of embedding a key directly in the header, the `jku` (JWK Set URL) parameter points to
where the verification key can be fetched from — a URL the server is expected to dereference and
pull a JWKS document from. That's a reasonable design for key rotation across a distributed system,
but it only stays safe if the server restricts which URLs it's willing to fetch keys from. Without
that restriction, `jku` becomes an invitation: point it anywhere, and the server will go get
whatever "trusted" key you left there.

## The Target

Same session/admin/delete structure as the other labs in this set. The server here fetches its
JWKS from a URL taken from the token's own `jku` header field, with no apparent domain allow-list
constraining where that URL is allowed to point.

## The Investigation

The exploitation path mirrors the `jwk` injection lab conceptually, but the key doesn't travel
inside the token itself — it travels at a URL the token names, and the server does the fetching.
That means we needed somewhere to actually host a JWKS document, which is exactly what
PortSwigger's per-lab exploit server provides. The plan: generate an RSA key pair, host a JWKS
document containing the public key at a URL on the exploit server, then set the token's `jku` to
that URL and sign with the matching private key. When the server processes the token, it fetches
our JWKS from our URL and verifies our signature against our own public key.

## The Exploit

We generated the RSA key pair and built both the forged token and the JWKS document to host,
in one step:

```python
def exploit_forge_jku_injection(jwt_token: str, new_claims: dict, jku_url: str) -> tuple[str, dict]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, ...)
    ...
    jwk = {"kty": "RSA", "e": ..., "n": ..., "kid": "exploit-key"}
    jwks = {"keys": [jwk]}

    header, payload, _ = decode_jwt(jwt_token)
    payload.update(new_claims)
    header["alg"] = "RS256"
    header["jku"] = jku_url
    header["kid"] = "exploit-key"
    ...
    sig = private_key.sign(signing_input, asym_padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{_b64url_encode(sig)}", jwks
```

We auto-detected the lab's assigned exploit server URL from a link on the lab page, pointed `jku`
at `{exploit_server}/exploit`, and hosted the generated JWKS JSON there by POSTing the exploit
server's response-configuration form (setting the response file path, status code, headers, and
body to our JWKS JSON, then storing it):

```python
r = client.post(exploit_server, data={
    "urlIsHttps": "on",
    "responseFile": "/exploit",
    "statusCode": "200",
    "responseHead": "HTTP/1.1 200 OK\r\nContent-Type: application/json",
    "responseBody": jwks_body,
    "formAction": "STORE"
})
```

With the JWKS hosted and the forged, `sub=administrator` token pointing its `jku` at it, requesting
`/admin` with that token as the session cookie succeeded, and the delete request against `carlos`
solved the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution splits into the same two halves: first, generate an RSA key pair in Burp's
JWT Editor Keys tab and upload a JWK Set (`{"keys":[...]}` populated with the generated public
key's parameters) to the exploit server's response body; second, edit the `GET /admin` request's
JWT — set `kid` to match the uploaded key, add a `jku` parameter pointing at the exploit server URL
hosting that JWK Set, change `sub` to `administrator`, and sign with the generated RSA key before
sending, then finish by hitting `/admin/delete?username=carlos`.

The mechanism is identical: attacker-hosted JWKS, `jku` pointed at it, token signed with the
matching private key. The difference is purely in how the exploit server gets configured — Burp's
GUI form for the exploit server versus our script's direct POST to the same form fields — and in
how the token itself gets built and signed, GUI editing through the JWT Editor extension versus our
`exploit_forge_jku_injection()` function generating and signing the token programmatically.

## What This Teaches Us

`jku` is a more dangerous variant of the `jwk` problem from the previous lab, because it doesn't
even require getting a payload past whatever might restrict inline header content — it just
requires convincing the server to make an outbound HTTP request to a URL of the attacker's
choosing, which is also, incidentally, an SSRF-shaped primitive in its own right depending on what
else the server's network position exposes. The fix that actually closes this off is a strict
allow-list of trusted `jku` hosts, validated before the server ever dereferences the URL — not
pattern-matching or substring checks on the URL string, which are exactly the kind of check that
URL-parsing tricks are designed to slip past.
