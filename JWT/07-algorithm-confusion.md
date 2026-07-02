# JWT authentication bypass via algorithm confusion

**Category:** JWT
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion

RS256 and HS256 both produce a JWT signature, but they mean completely different things. RS256 is
asymmetric — sign with a private key, verify with a matching public key that's safe to publish.
HS256 is symmetric — the exact same secret both signs and verifies, so anyone who has it can forge
tokens freely. Algorithm confusion happens when a server's verification function is
algorithm-agnostic: it reads whatever `alg` the incoming token declares and blindly applies that
algorithm's verification logic against whatever key material it has configured for that user, even
if that key material was never meant to be used symmetrically. That mismatch turns a public key —
something the server hands out on purpose — into a secret it didn't know it was exposing.

## The Target

The lab uses RS256-signed session tokens, with the server's public key exposed at the standard
`/jwks.json` endpoint as a JWK Set. The `/admin`-panel-and-delete-`carlos` structure is the same as
every other lab in this set.

## The Investigation

If the server's `verify(token, key)` call is written to accept whatever algorithm the token's
header specifies rather than enforcing RS256 specifically, then changing `alg` to `HS256` makes the
server treat its own RSA *public* key as an HMAC *secret*. Since the public key is, by design,
not secret at all — it's published at `/jwks.json` precisely so clients can verify tokens — an
attacker who can read it now has everything needed to sign HS256 tokens the server will accept as
genuine.

The subtlety that actually made this work is key formatting: the server stores and uses its public
key internally as PEM-encoded bytes, specifically in X.509 SubjectPublicKeyInfo format rather than
PKCS1. If the HMAC secret bytes we sign with don't match that exact byte representation — extra
whitespace, wrong PEM header/footer text, or PKCS1 instead of X.509 encoding — the signatures won't
match even though the underlying RSA key is correct. We fetched the JWKS, decoded the modulus and
exponent, and reconstructed the public key with the `cryptography` library specifically using
`serialization.PublicFormat.SubjectPublicKeyInfo` to guarantee a byte-for-byte match with whatever
format the server has cached internally.

## The Exploit

We fetched `/jwks.json`, took the first key's `n` and `e` values, and rebuilt the RSA public key as
PEM:

```python
jwk = ctx.jwks_keys[0]
e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
pub = RSAPublicNumbers(e, n).public_key(default_backend())
pem = pub.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
).decode()
```

then forged a token by changing `alg` to `HS256` and signing with that PEM's raw bytes as the HMAC
key:

```python
def exploit_algo_confusion(jwt_token: str, new_claims: dict, public_key_pem: str) -> str:
    header, payload, _ = decode_jwt(jwt_token)
    payload.update(new_claims)
    header["alg"] = "HS256"
    return encode_jwt(header, payload, public_key_pem.encode(), "HS256")
```

with `sub` set to `administrator`. Setting the resulting token as the session cookie and requesting
`/admin` succeeded on the first attempt — the server's `verify(token, publicKey)` call computed an
HMAC using the same PEM bytes we had, producing a matching signature. The delete request against
`carlos` solved the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution runs through Burp's JWT Editor extension in three parts: fetch the exposed
JWK from `/jwks.json`, paste it into the extension's Keys tab as a new RSA key, copy that key's
public portion out as PEM, Base64-encode the PEM, then create a *new symmetric key* whose `k`
property is set to that Base64-encoded PEM value. From there, editing the `GET /admin` request's
JWT — `alg` to `HS256`, `sub` to `administrator` — and signing with the newly created symmetric key
produces the forged token.

The technique is identical: obtain the public key, treat its PEM bytes as an HMAC secret, sign an
`HS256`-declared token with it. The one detail worth flagging is that Burp's workflow explicitly
Base64-encodes the PEM before storing it as the symmetric key's `k` value, because JWT Editor's
symmetric key format expects `k` to be Base64-encoded key material — but the actual bytes HMAC'd
against the signing input are still the raw PEM bytes once decoded back out, so this is a storage
convention inside the extension, not a difference in what gets signed. Our
`exploit_algo_confusion()` skips that intermediate representation and calls Python's `hmac` module
directly on the PEM's raw encoded bytes, reaching the same signature.

## What This Teaches Us

Algorithm confusion is a sharp illustration of why "the key is safe to publish" and "the key is
safe to use for this specific cryptographic operation" are not the same claim. An RSA public key is
only safe to expose under the assumption that it will only ever be used as an RSA public key —
the moment a verification function is willing to reinterpret it as an HMAC secret instead, that
publication assumption breaks silently. The fix is the same strict algorithm enforcement that
closes off the `alg: none` bug from an earlier lab in this set: a server configured to expect RS256
must reject any token declaring a different algorithm before it ever reaches the point of choosing
which key material to verify against.
