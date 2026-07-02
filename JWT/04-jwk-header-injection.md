# JWT authentication bypass via jwk header injection

**Category:** JWT
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jwk-header-injection

The JWT header can carry more than just an algorithm name — the `jwk` parameter lets a token embed
the actual public key that should be used to verify it. That's a legitimate part of the JOSE
specification for scenarios with rotating or per-token keys, but it inverts the trust relationship
if the server ever honors a key supplied by the token itself instead of only trusting keys from its
own, separately maintained keystore. If the token gets to say which key proves it's authentic, an
attacker can just generate their own key pair and have the token vouch for itself.

## The Target

The familiar JWT-session, `/admin`-panel, delete-`carlos` shape. The header here uses RS256, and
critically the server appears willing to read a `jwk` field directly out of the incoming token's
header when selecting a verification key, rather than only consulting its own trusted key store.

## The Investigation

If the server's verification logic pulls the key to use from `header.jwk` rather than looking it
up by `kid` against a fixed, server-side set of trusted keys, then the entire RS256 signature check
becomes attacker-controlled: generate a fresh RSA key pair, embed the *public* half directly in the
JWT header as a `jwk` object, and sign the token with the matching *private* half. The signature
will verify successfully because the server is checking it against the exact key the token brought
along with it — there was never a comparison against a key the server actually owns.

## The Exploit

We generated a new 2048-bit RSA key pair per forgery attempt, built the JWK object from its public
numbers, embedded it in the header alongside a matching `kid`, and signed with the private key:

```python
def exploit_forge_jwk_injection(jwt_token: str, new_claims: dict) -> str:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, ...)
    public_key = private_key.public_key()
    pub_numbers = public_key.public_numbers()

    jwk = {
        "kty": "RSA",
        "e": _b64url_encode(pub_numbers.e.to_bytes(...)),
        "n": _int_to_b64url(pub_numbers.n),
        "kid": "exploit-key"
    }

    header, payload, _ = decode_jwt(jwt_token)
    payload.update(new_claims)
    header["alg"] = "RS256"
    header["jwk"] = jwk
    header["kid"] = "exploit-key"
    ...
    sig = private_key.sign(signing_input, asym_padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{_b64url_encode(sig)}"
```

with the payload's `sub` claim set to `administrator`. Sending the resulting token as the session
cookie to `/admin` succeeded — the server verified the signature using the RSA public key we'd
handed it in the header, which of course matched, since we'd signed with the corresponding private
key ourselves. The delete request against `carlos` from there solved the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution runs the same attack through Burp's JWT Editor extension: generate a new RSA
key pair in the extension's Keys tab, open the `GET /admin` request's JSON Web Token editor tab,
change `sub` to `administrator`, then use the "Embedded JWK" attack option to have Burp
automatically embed the generated key's public half into the header and sign with the private half
— noting that manual embedding is also possible as an alternative to the built-in attack shortcut.

This is the same technique end to end — generate a key pair, embed the public key in the header,
sign with the private key. The difference is that Burp's Embedded JWK feature automates the
"generate, embed, sign" sequence behind one GUI action, while our `exploit_forge_jwk_injection()`
function does the equivalent key generation and JWK construction directly in Python using the
`cryptography` library, giving the same forged token without needing the JWT Editor extension
installed.

## What This Teaches Us

Any header parameter that can influence *which key gets used* to verify a signature has to be
treated as untrusted input, because a signature check is only meaningful when the key came from
somewhere the server actually controls. `jwk`, and the closely related `jku` and `kid` parameters
covered in the next two labs, are all variations on the same underlying mistake: letting the token
itself point to its own verification key rather than requiring every key to be resolved from a
fixed, server-side keystore. The fix is to never resolve keys from token-supplied `jwk` data at
all — verification keys should come exclusively from a pre-established, server-controlled source.
