# JWT authentication bypass via algorithm confusion with no exposed key

**Category:** JWT
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion-with-no-exposed-key

The previous lab's algorithm confusion attack depends on one convenience: a `/jwks.json` endpoint
handing over the server's public key for free. This lab removes that convenience entirely — no
JWKS endpoint, no published key anywhere — and asks whether the same attack is still possible. It
is, because RSA's own mathematics leaks enough information across two signatures from the same key
to reconstruct the public modulus without ever being told what it is.

## The Target

Identical RS256-session, `/admin`-panel, delete-`carlos` structure to the previous lab, but with no
`/jwks.json` or `/.well-known/jwks.json` endpoint exposed anywhere on the target.

## The Investigation

Without a published key, we needed to derive the server's RSA public key mathematically — the
technique PortSwigger's own tooling calls `sig2n`. The underlying math: for an RSA signature `s`
over a padded message hash `m` with public exponent `e`, `s^e mod n == m`, which means
`s^e - m` is an exact multiple of `n`. Two signatures produced by the *same* key give two such
multiples, `s1^e - m1 = k1*n` and `s2^e - m2 = k2*n`, and `n = gcd(s1^e - m1, s2^e - m2)` after
removing small extraneous prime factors that the GCD can pick up incidentally.

Reconstructing `m` (the PKCS#1 v1.5-padded SHA-256 hash of the signing input) requires building the
padding by hand: `0x00 0x01 [0xFF-bytes] 0x00 [DigestInfo] [SHA-256 hash]`, where the DigestInfo
prefix for SHA-256 is the fixed byte string `3031300d060960864801650304020105000420`. We computed
this for two JWTs obtained from two separate logins (needing two, since the derivation requires two
independent signatures from the same key), for candidate key sizes of 2048 and 4096 bits, since the
padding length depends on knowing the key size in advance:

```python
def _jwt_sig_and_padded(jwt_str: str, key_bits: int):
    parts = jwt_str.split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    sig_bytes = _b64url_decode(parts[2])
    sig_int = gmpy2.mpz(int.from_bytes(sig_bytes, "big"))

    h = hashlib.sha256(signing_input).digest()
    key_bytes = key_bits // 8
    t = DIGEST_INFO + h
    ps_len = key_bytes - len(t) - 3
    padded = b"\x00\x01" + (b"\xff" * ps_len) + b"\x00" + t
    padded_int = gmpy2.mpz(int.from_bytes(padded, "big"))
    return sig_int, padded_int
```

PortSwigger ships a `sig2n` Docker tool that does this same computation, but running the math
ourselves needed real big-integer arithmetic at RSA-scale exponents — `s^65537` on a 2048-bit
integer is far beyond what Python's built-in arbitrary-precision integers handle quickly. We used
`gmpy2` (GMP-backed) for the modular exponentiation and GCD steps specifically because it's fast
enough to make this tractable outside the Docker container, replacing the `sig2n` tool with an
equivalent pure-Python-plus-gmpy2 implementation.

After computing the GCD candidate for `n`, we stripped small prime factors (2, 3, 5, 7, up through
47) that can ride along in the GCD result without being genuine factors of the actual modulus, then
checked the remaining value's bit length landed within a few bits of the expected key size before
accepting it as a real candidate.

## The Exploit

We logged in twice to get two distinct JWTs signed by the same server key (retrying with a short
delay if the two logins returned identical tokens, in case of caching), derived candidate PEM
public keys for both 2048-bit and 4096-bit assumptions, then ran the same algorithm-confusion
forgery from the previous lab against each candidate key in turn:

```python
for i, pem in enumerate(pem_keys):
    forged = exploit_algo_confusion(session1, {"sub": "administrator"}, pem)
    if _admin_delete_carlos(client, lab_url, forged):
        return
```

`exploit_algo_confusion()` is the same function as the previous lab — build the token with `alg`
set to `HS256`, `sub` set to `administrator`, and sign with the derived key's PEM bytes as the HMAC
secret. This solved on the first attempt with the gmpy2-accelerated derivation, without needing to
fall back to the Docker `sig2n` tool.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the same four-part structure: obtain two JWTs from two separate
logins; run `docker run --rm -it portswigger/sig2n <token1> <token2>` to brute-force candidate
public keys, which prints several X.509/PKCS1 candidate PEMs since the small-factor stripping can
leave more than one plausible value; test each candidate by swapping it into the session cookie in
Repeater and checking for a `200` (correct key) versus `302` (wrong key) response; then take the
Base64-encoded X.509 key that worked, load it as a symmetric key in Burp's JWT Editor, and run the
same `alg`-to-`HS256`, `sub`-to-`administrator` forgery as the previous lab.

The mathematics — GCD of two `s^e - m` values, small-factor removal, X.509-format PEM reconstruction
— is exactly what their `sig2n` Docker tool automates internally, and exactly what we reimplemented
directly in Python. The meaningful difference is that PortSwigger's path treats `sig2n` as an opaque
Docker container producing several candidate keys to try manually against `200`-vs-`302` responses,
while we implemented the underlying derivation ourselves with `gmpy2` for the heavy arithmetic and
looped through the 2048-bit and 4096-bit candidates programmatically, checking each by attempting
the full admin-panel-and-delete flow rather than inspecting status codes by hand.

## What This Teaches Us

This lab shows that "we don't publish the public key" is not a meaningful mitigation for algorithm
confusion — RSA signatures leak enough structure that the public key can be recovered from any two
signatures produced by the same private key, entirely offline, with no server interaction beyond
obtaining two ordinary session tokens. Security that depends on a value being merely *unpublished*
rather than actually *secret* is fragile in exactly this way. The real fix, as with the previous
lab, is strict algorithm enforcement on the server side: a token declaring `HS256` should never be
evaluated against a key that was generated and intended for RS256, regardless of whether that key
was ever exposed directly, indirectly, or not at all.
