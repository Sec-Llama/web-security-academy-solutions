# Broken brute-force protection, multiple credentials per request

**Category:** Authentication
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/authentication/password-based/lab-broken-brute-force-protection-multiple-credentials-per-request

Every brute-force protection built in this series so far assumed one HTTP request equals one login attempt. That assumption is the entire defense — and it only holds if the server actually enforces it. This lab's login endpoint accepts JSON, and JSON lets a single field hold an array instead of a string.

## The Target

The login form's `POST /login` request, submitted as `Content-Type: application/json`, carries a `username` and `password` field like any other login endpoint. Nothing on the surface suggests it behaves differently from the form-encoded logins in every other lab in this series.

## The Investigation

The behavior we confirmed and recorded is blunt: the server accepts the `password` field as either a single string or a JSON array of strings, and if it's an array, it tests every value in it against the account. One request, N password attempts, and — critically — whatever rate limiting or lockout logic exists is counting *requests*, not *attempts*, so it never notices a hundred guesses arrived disguised as one.

## The Exploit

`exploit_multi_cred_request` (wired up as `lab_13_multi_cred`) sends exactly one `POST /login` request:

```
POST /login
Content-Type: application/json

{"username": "carlos", "password": [<all 100 candidate passwords>]}
```

No session, no cookie jar setup, no prior requests needed — this works as a completely cold, unauthenticated POST. Per our verified notes, a correct password anywhere in the array produces a `302` redirect, exactly like a normal successful login would. The script checks for that `302` status directly, and as a fallback, follows any redirect and checks whether the resulting page is authenticated. The single request either returns a redirect (meaning one of the hundred embedded guesses matched) or it doesn't — and here it did, solving the lab in one HTTP round trip with zero brute-force attempts in the traditional sense.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the same request shape: intercept the login `POST`, note that it's JSON, and in Burp Repeater replace the string password value with an array containing all the candidate passwords — `"password": ["123456", "password", "qwerty", ...]` — then send it once. The resulting `302` is loaded in the browser via Repeater's "Show response in browser," and clicking through to "My account" confirms the solve.

This is another case of identical technique with different tooling: PortSwigger edits the JSON body by hand in Repeater and manually forwards the resulting session cookie into a browser tab. Our script builds the same array programmatically from the full candidate wordlist and detects success directly off the response rather than a manual browser hop.

## What This Teaches Us

The vulnerability isn't a missing rate limiter — the login endpoint probably does count requests correctly. It's a type-confusion gap between what the request-counting logic expects (one credential pair per request) and what the authentication logic actually accepts (an array of credentials evaluated in a loop). Any endpoint that accepts structured input needs its brute-force protection to account for cardinality inside the payload, not just the request rate — otherwise an attacker doesn't need many requests at all, just one sufficiently large one.
