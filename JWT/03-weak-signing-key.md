# JWT authentication bypass via weak signing key

**Category:** JWT
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key

HS256 tokens are only as strong as the secret behind them, and that secret is symmetric — the same
value both signs and verifies. If a developer picks something short, guessable, or copy-pasted from
a tutorial, the entire trust model collapses the moment an attacker can recover that string,
because knowing the secret means being able to forge arbitrary valid tokens, not just read
existing ones.

## The Target

Another JWT-cookie session, another `/admin` panel gated to `administrator`, another delete action
for `carlos` once inside. This time the header declares `HS256`, meaning the signature is an
HMAC computed over the token using some server-side secret key we don't have — but might be able to
guess.

## The Investigation

Because HS256 verification is just "recompute the HMAC with a candidate secret and compare," a
weak secret is a brute-forceable secret: try candidates, recompute, check for a match. We built
this as pure Python HMAC verification for wordlist attacks, with hashcat's Collaborator-mode
approach documented as the alternative for larger wordlists:

```python
def _try_secret(candidate: str):
    computed = hmac.new(candidate.encode(), signing_input, hash_func).digest()
    if hmac.compare_digest(computed, expected_sig):
        return candidate
    return None
```

run across a set of candidates including a small built-in default list and, for real brute-forcing,
a dedicated wordlist. Against this lab's token we used our `jwt_secrets.txt` wordlist (104K
entries) with the pure-Python HMAC checker, and it found the match instantly: the secret was
`secret1`.

## The Exploit

With the secret known, forging an admin token is direct — decode the original, change the `sub`
claim, and re-sign with HMAC-SHA256 using the recovered secret:

```python
def exploit_forge_with_secret(jwt_token: str, secret: str, new_claims: dict) -> str:
    header, payload, _ = decode_jwt(jwt_token)
    payload.update(new_claims)
    return encode_jwt(header, payload, secret.encode(), header.get("alg", "HS256"))
```

Signing `{"sub":"administrator", ...}` with `secret1` produced a token whose signature the server
accepted as valid, because it's computed with the exact same key the server uses to verify.
Setting that as the session cookie and requesting `/admin` returned the panel, and the delete
request for `carlos` solved the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution uses Burp's JWT Editor extension end to end: brute-force the secret with
`hashcat -a 0 -m 16500 <jwt> /path/to/jwt.secrets.list` (the same wordlist source, same result —
`secret1`), Base64-encode the recovered secret in Burp's Decoder, create a new symmetric key in
the JWT Editor Keys tab with that encoded value as the `k` property, then use the JSON Web Token
editor tab to change `sub` to `administrator` and sign with the generated key before sending.

The brute-force target and the forged claim are identical between the two approaches. The
divergence is entirely in tooling: PortSwigger's path uses hashcat as an external process plus
Burp's JWT Editor extension for key management and signing, while ours ran the same wordlist
through a pure-Python HMAC checker and handled the re-signing with our own `encode_jwt()` helper —
useful specifically because it doesn't depend on having Burp's JWT Editor extension loaded, and
scales the same way to any wordlist size since the check itself is a cheap HMAC comparison, not a
network request.

## What This Teaches Us

Algorithm strength is irrelevant if the key behind it is weak — HS256 itself is not a broken
primitive, `secret1` as its key is. This lab is really a password-strength problem wearing a
cryptography costume: the same category of mistake as a weak login password, just applied to a
signing key that, once cracked, doesn't just unlock one session but grants the ability to mint
arbitrary sessions for any user, including one that doesn't yet exist. The fix is a long,
randomly generated, unique HMAC secret that's never derived from a dictionary word or example
value — and, more robustly, moving to asymmetric signing (RS256) so that even a fully exposed
verification key can't be used to forge new tokens.
