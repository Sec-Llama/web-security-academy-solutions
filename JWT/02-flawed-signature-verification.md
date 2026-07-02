# JWT authentication bypass via flawed signature verification

**Category:** JWT
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification

The JWT specification includes an algorithm called `none`, meant for situations where a token's
integrity is already guaranteed some other way and no signature is needed at all. That's a
reasonable feature on paper and a dangerous one in practice, because it means the token itself
gets to declare "don't bother checking my signature" — and if the server's verification code
trusts that declaration blindly, an attacker can just ask for no verification at all.

## The Target

Same shape of application as the previous lab: a JWT-based session cookie, an `/admin` panel
gated to the `administrator` user, and a `/admin/delete?username=carlos` action once inside. The
difference here is that this server does call a real verification routine — it just doesn't
restrict which algorithms that routine is willing to accept.

## The Investigation

Where the previous lab skipped verification entirely, this one is the more common real-world
version of the same class of bug: the server checks the `alg` field in the token header and
verifies accordingly, but never enforces an algorithm whitelist. That means a token that declares
itself `"alg":"none"` can tell the server "there's nothing to verify here" and be trusted anyway.
The catch is that a `none`-algorithm JWT still has to look structurally like a JWT — header, dot,
payload, dot, and then nothing, with the trailing dot for the empty signature segment still
required or the token won't parse as three parts.

We also kept in mind that some implementations filter for the literal string `"none"` case-
sensitively, so it's worth testing case variants — `"None"`, `"NONE"`, `"nOnE"` — in case the
comparison is naive.

## The Exploit

We logged in to get a genuine token, then rebuilt it with the algorithm changed and the signature
dropped:

```python
def exploit_forge_none(jwt_token: str, new_claims: dict) -> str:
    header, payload, _ = decode_jwt(jwt_token)
    header["alg"] = "none"
    payload.update(new_claims)
    return encode_jwt(header, payload, algorithm="none")
```

which produces a token of the shape:

```
{"alg":"none","typ":"JWT"}.{"sub":"administrator"}.
```

— Base64url header, Base64url payload with `sub` set to `administrator`, and a trailing dot with
nothing after it. Sending that as the session cookie to `/admin` succeeded, and the delete request
for `carlos` from the admin panel solved the lab. Our detection routine also verifies this class of
bug generally by systematically trying the `none`/`None`/`NONE`/`nOnE` casing variants against a
target's `/my-account` endpoint, in case a naive string filter is in play rather than a full
algorithm-whitelist gap.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the same idea through Burp's JWT Inspector: log in, send the
post-login request to Repeater, change the path to `/admin`, edit the `sub` claim to
`administrator`, then select the token's header and change `alg` to `none` via the Inspector. The
final manual step is to open the message editor and delete the signature segment by hand — while
being careful to leave the trailing dot after the payload, since removing that dot would make the
token fail to parse as three (even if empty) parts. That's the same requirement our automated
`encode_jwt()` handles unconditionally when the algorithm is `none`.

The underlying flaw and the exploitation logic are identical between the two approaches — the only
difference is that Burp's Inspector edits the token fields and reassembles it through GUI actions,
while our Python helper does the same reconstruction programmatically.

## What This Teaches Us

The header of a JWT is attacker-controlled input, exactly like every other part of the token, which
makes "trust whatever algorithm the header says to use" equivalent to letting the client pick its
own authentication requirements. `alg: none` is the sharpest version of that mistake because it
lets the client opt out of authentication entirely, but the same root cause — accepting an
algorithm from the token instead of enforcing one chosen by the server — is what makes the
algorithm-confusion labs later in this series work too. The fix here is a strict, server-side
algorithm whitelist that never includes `none`, checked before any other part of verification runs,
regardless of what the incoming token's own header claims.
