# 2FA broken logic

**Category:** Authentication
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic

The previous lab's fix — actually enforcing that a 2FA code gets verified before granting access — still isn't enough if the server doesn't check *whose* code it's verifying. If the value that decides which account's code to validate against comes from something the client controls, an attacker doesn't need to guess anyone else's password at all; they just need to point the verification step at a different account.

## The Target

After password login, the app sets a `verify` cookie alongside the session and presents a code-entry form at `/login2`. The natural assumption is that the server checks the submitted code against whichever account is tied to the authenticated session — but per our notes, it instead reads the `verify` cookie to decide which user's 2FA code to check.

## The Investigation

We had valid credentials for our own account (`wiener:peter`) and a target username (`carlos`) whose password we didn't know and didn't need. The exploit chain, encoded in `exploit_2fa_logic_flaw`, works in three steps:

1. **Establish a session as ourselves.** `POST /login` with `wiener:peter` captures a session cookie — this is what keeps the request "authenticated" from the server's point of view.
2. **Override the `verify` cookie to the victim.** Setting `verify=carlos` on that same session and issuing `GET /login2` triggers the server to generate a fresh 2FA code — for `carlos`, not for `wiener`. The server never questioned why an authenticated `wiener` session would be asking to verify a code for a different username.
3. **Brute-force the 4-digit code against that session.** With the `verify` cookie still pinned to `carlos`, `POST /login2` with `mfa-code` swept across `0000`–`9999`.

One detail from our notes was important to get right during detection: checking the final URL after following redirects (`/my-account` in `resp.url`) rather than scanning the response body for text, because navigation links elsewhere on the page caused false positives when matched against raw body content. There was also no CSRF protection on the `/login2` form in this lab, which simplified the brute-force loop — no token to refresh between attempts.

## The Exploit

The brute-force ran concurrently across 10 workers, each carrying its own `httpx` client with the session and `verify=carlos` cookies, POSTing a different candidate code and checking whether the final redirected URL landed on `/my-account`. Per our verified notes, this took roughly 10,000 attempts in the worst case to exhaust the 4-digit keyspace, and concurrent execution across the full range completed without the server showing any sign of rate-limiting the verification endpoint. The winning code authenticated the session as `carlos`, and loading `/my-account` confirmed the account takeover and solved the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the same three-step logic: log in as yourself, send `GET /login2` with the `verify` parameter changed to `carlos` to trigger code generation for that account, then send an invalid code once to reach a legitimate `POST /login2` request, hand that off to Burp Intruder with `verify` fixed to `carlos` and a payload position on `mfa-code`, and brute-force until a `302` appears.

The underlying flaw and exploitation path are identical between the two approaches — the `verify` parameter, not session identity, is what the server actually trusts. The real difference is throughput: PortSwigger's Intruder attack runs its 10,000 requests sequentially through one client, while our script ran the same sweep across 10 concurrent workers, each with an independent client, cutting wall-clock time substantially for a keyspace that size.

## What This Teaches Us

Binding a second factor's identity to a client-supplied value instead of the authenticated session is the same class of mistake as trusting a client-supplied user ID in an IDOR — the server has an authenticated principal (`wiener`, from the session) and chose to trust something else (`verify=carlos`, from a cookie) instead. The fix is to derive "whose code is being checked" exclusively from server-side session state, never from a value the client can simply overwrite.
