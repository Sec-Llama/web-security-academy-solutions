# Brute-forcing a stay-logged-in cookie

**Category:** Authentication
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/authentication/other-mechanisms/lab-brute-forcing-a-stay-logged-in-cookie

Every brute-force protection in this series so far lives on the login endpoint. A "remember me" cookie sidesteps the login endpoint entirely — if that cookie is just a predictable encoding of a username and a password hash, an attacker never has to submit a single login attempt to forge it.

## The Target

Checking "Stay logged in" during login sets a `stay-logged-in` cookie. Per our notes, decoding it revealed the format: base64 of `username:md5(password)` — a plaintext username next to an unsalted MD5 hash of the account's password, with no server-side randomness involved at all.

## The Investigation

Because the cookie is entirely self-contained and deterministic, we didn't need to interact with the login form to test candidate values — we could construct a candidate cookie offline and simply present it as a header on `GET /my-account`. The value being unsalted MD5 is what makes this practical: for any candidate password, computing `md5(password)`, prefixing it with `carlos:`, and base64-encoding the result reproduces exactly what the server would have generated had `carlos` actually logged in with that password.

## The Exploit

`exploit_cookie_brute` runs that construction across the full 100-entry candidate password list:

```python
for pw in passwords:
    cookie = base64.b64encode(f"carlos:{hashlib.md5(pw.encode()).hexdigest()}".encode()).decode()
```

Each candidate cookie value was sent as `Cookie: stay-logged-in=<cookie>` on `GET /my-account`, concurrently across 10 workers. A hit was confirmed by a `200` response containing no "log in" prompt and the target username present in the body. Per our verified notes, this bypasses login rate limiting entirely — no login attempts were ever made, only direct `/my-account` requests carrying a forged authentication cookie, so the endpoint that actually has brute-force protection (`/login`) was never touched.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution builds the same forged cookie inside Burp Intruder using its payload-processing pipeline: take the candidate password list, apply a **Hash (MD5)** processing rule, then **Add prefix** `carlos:`, then **Base64-encode**, producing exactly the cookie value our script computes directly in Python. A grep-match rule on the string "Update email" (only present in the authenticated account page) flags the winning candidate.

This is a case of identical technique, different execution surface: Burp's three-stage payload transform chain does the same hash-prefix-encode sequence our `hashlib`/`base64` calls do, just configured through the GUI instead of written as code. Both approaches confirm success the same way — a marker string only present once actually authenticated.

## What This Teaches Us

A "remember me" mechanism built from a deterministic function of static account data (username plus a password hash, unsalted) is functionally an offline-crackable secret disguised as a session token. Because no randomness is involved, the cookie can be reconstructed entirely outside any rate-limited endpoint — the fix is a long, cryptographically random token generated server-side and stored against the account, with no derivable relationship to the username or password whatsoever.
