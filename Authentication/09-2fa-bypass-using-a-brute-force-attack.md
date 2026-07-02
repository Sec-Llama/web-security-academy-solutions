# 2FA bypass using a brute-force attack

**Category:** Authentication
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-bypass-using-a-brute-force-attack

A 4-digit code is only 10,000 possibilities — trivial to exhaust if the server lets you keep guessing against one fixed value. This lab doesn't let you: two wrong codes and the session is logged out entirely, and the code itself gets thrown away in the process. Brute-forcing it means brute-forcing the *entire login flow*, not just one form field.

## The Target

After password login, `/login2` prompts for a 4-digit `mfa-code`. Per our notes, submitting two incorrect codes logs the session out completely — there's no persistent session left to keep guessing against, and each fresh login generates a brand-new code, invalidating any code you were previously trying to brute-force partway through.

## The Investigation

The known credentials (`carlos:montoya`) were given by the lab; the challenge was entirely about attack shape, not credential discovery. Because the code resets on every fresh login, there's no way to run a clean sequential sweep of `0000`–`9999` against one static secret the way the previous lab's brute-force did. Instead, each individual guess has to be treated as an independent trial: log in fresh, get whatever code the server generated this time, guess once, and if wrong, the session is gone and you start over. That turns brute-forcing 10,000 codes into 10,000 full re-authentication cycles, each with roughly a 1-in-10,000 chance of guessing that cycle's particular code correctly — a probabilistic attack rather than a deterministic keyspace exhaustion.

## The Exploit

`exploit_2fa_brute_relogin` implements exactly that cycle per attempt: `POST /login` with the known credentials, extract a fresh CSRF token from the resulting `/login2` page, then `POST /login2` with one candidate `mfa-code` and check whether the final URL (after following redirects) lands on `/my-account`. The wrapper ran this with 20 concurrent workers, each executing the full independent re-login cycle rather than sharing a session — since every attempt regenerates its own code, there was no synchronization needed between workers.

Per our verified notes, the math works out to roughly a 63% chance of success after 10,000 total attempts, climbing to around 95% after 30,000. `lab_14_2fa_brute_relogin` accounts for that by wrapping the attack in up to five passes, retrying the full 10,000-code sweep again if the previous pass came back empty, since a single pass isn't guaranteed to land a hit even at full keyspace coverage. Once a matching code did land, the wrapper explicitly reran the login and code submission for that value on a clean session, since finding the code mid-sweep on a worker thread doesn't necessarily leave the *lab's own tracked browser session* authenticated — the same "solve state lives in one specific session" behavior we'd already run into in other labs in this series.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution builds a Burp session-handling rule with a macro — `GET /login`, `POST /login`, `GET /login2` — set to run automatically before each Intruder request, so that every one of the 10,000 numeric payloads Intruder sends is preceded by a fresh, valid re-login. Their resource pool is set to `Maximum concurrent requests = 1`, running the whole attack sequentially, though the solution notes that concurrent requests also work.

The underlying mechanism is identical: since the code can't be attacked as a static secret, both approaches wrap the entire login sequence into a single repeatable "attempt" unit. The meaningful difference is concurrency — PortSwigger's default walkthrough runs sequentially through Burp's session-handling macro, while we ran 20 independent workers each performing their own full re-login cycle, since nothing about this vulnerability requires the attempts to be ordered relative to each other (unlike the IP-block-bypass lab earlier in this series, where strict ordering was essential). That concurrency is also why our script needed the multi-pass retry logic: 20 workers racing independently against a 1-in-10,000 target per cycle converges on the same probabilistic outcome PortSwigger's sequential sweep does, just faster.

## What This Teaches Us

Locking out a session after two wrong 2FA attempts looks like strong protection, but it only stops brute-forcing *within* a session — it does nothing if re-authentication itself isn't rate-limited or throttled. The real gap is that the login endpoint will hand out a fresh 2FA challenge as many times as asked, with no cost or delay between full login cycles. Effective protection here needs to rate-limit or lock out *account-level* 2FA attempts across sessions, not just within one, and ideally add a cost (CAPTCHA, exponential backoff) to repeated fresh logins targeting the same account.
