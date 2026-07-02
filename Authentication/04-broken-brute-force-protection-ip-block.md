# Broken brute-force protection, IP block

**Category:** Authentication
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/authentication/password-based/lab-broken-bruteforce-protection-ip-block

Rate limiting that only counts *consecutive* failures has a blind spot: it assumes an attacker only ever sends failures. Slip one successful login in between guesses and the counter never has a chance to reach its threshold — the protection resets itself on your behalf, over and over, for as long as you're willing to keep alternating.

## The Target

The login endpoint blocks the source IP after three incorrect login attempts in a row. Our own credentials (`wiener:peter`) are valid and always succeed — the question is what "in a row" actually means to the counter.

## The Investigation

The behavior our notes confirm is that a successful login resets the failed-attempt counter entirely, not just for that account but for the IP-level block state. That turns the three-strikes rule into something bypassable by construction: as long as a valid login happens before the counter reaches three, it never fires.

`exploit_ip_block_bypass` in `Authentication.py` encodes that directly: for each candidate password in the 100-entry list, the client first sends `POST /login username=wiener&password=peter` — a guaranteed success that resets the counter — and only then sends the real guess, `POST /login username=carlos&password=<candidate>`. This has to run strictly sequentially, one request at a time, because the reset only helps if it lands *before* the block would otherwise trigger; if the reset and the guess race each other out of order, the block state doesn't get cleared in time. The function is documented in our source as intentionally sequential for exactly this reason.

## The Exploit

The loop checked each `carlos` attempt for a `302` status or a redirect path containing `my-account`, and as a secondary check, confirmed the response contained no `incorrect`/`invalid`/`blocked`/`too many` text before verifying via a follow-up `/my-account` request. The first password that produced a real authenticated response was `carlos`'s actual password, found without ever tripping the IP block — because the block's own three-in-a-row counter was reset by our own valid login immediately before every single guess.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution builds the identical alternating pattern through Burp Intruder: a Pitchfork attack with two payload lists running in lockstep — one alternating between the attacker's own username and `carlos`, the other alternating between the attacker's own correct password and each candidate password — with the resource pool's **Maximum concurrent requests** explicitly set to `1` so the pairs fire in strict order. Results are filtered to hide `200` responses and sorted by username, leaving a single `302` for `carlos` with the matching password in the adjacent payload column.

This is a case where our script and PortSwigger's walkthrough land on the exact same technique, byte for byte: alternate a known-good login with each guess, keep it strictly sequential, watch for the one `302`. The only real difference is mechanical — Burp's Pitchfork attack with a resource pool cap versus a single-threaded Python loop that does the same alternation natively. Neither approach could be run concurrently and still work; the ordering is the whole point.

## What This Teaches Us

Brute-force protection that resets on *any* success, rather than tracking failures per account independently of what else happens on that IP, isn't really protection — it's a counter an attacker can zero out on demand. The fix has to track failed attempts against the *target* account specifically (or bind the block to a combination that a valid unrelated login can't reset), and ideally shouldn't allow unrelated successful logins to erase in-progress lockout state for a different account entirely.
