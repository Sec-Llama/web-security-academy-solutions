# Bypassing rate limits via race conditions

**Category:** Race Conditions
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/race-conditions/lab-race-conditions-bypassing-rate-limits

Rate limiting is one of the standard answers to brute-force login attacks — lock an account, or an
IP, after a handful of failed attempts and the search space for guessing a password stops mattering.
That defense has its own unstated assumption, though: that "three failed attempts" is counted
atomically, request by request, in order. If the counter is instead a value that gets read, then
incremented, in two separate steps, a burst of simultaneous guesses can all read the same
pre-lockout count before any of them get around to incrementing it — turning a rate limit into a
speed bump rather than a wall.

## The Target

The login form at `/login` accepts `username` and `password` and, after roughly three failed
attempts for a given username, starts rejecting further attempts with a "you have made too many
incorrect login attempts" style response regardless of whether the password is correct. Our goal
was to recover the password for `carlos`, log in, and use the admin panel to delete that account.

## The Investigation

The lockout is clearly enforced per-username, and clearly effective against attempts sent one at a
time. But "effective against sequential attempts" and "effective against simultaneous attempts" are
different claims. If the failed-attempt counter is checked at the start of request handling and
only incremented once the login has been fully processed, then a batch of login attempts that all
arrive before the first one finishes processing will all see the same "not yet locked out" counter
value — meaning a wrong password sent inside that window gets a real answer instead of a
rate-limited rejection, and, critically, so does the *correct* password if it happens to be in that
same batch.

That reframes the brute-force problem: instead of guessing one password at a time against a
shrinking attempt budget, we send an entire candidate list in one race window and only need the
correct password to be somewhere inside that window's small number of "before lockout" slots.

Our first implementation reused the same raw HTTP/2 single-packet socket engine from the previous
lab — building all the login requests as HTTP/2 frames and flushing them in one `sock.sendall()`.
Against this login endpoint that approach didn't come back with useful results: the server never
responded to our connection preface, so we got nothing back at all rather than a clean signal one
way or the other. Rather than debug the raw socket handshake further, we switched engines: an
`httpx.AsyncClient` with `http2=True`, firing all requests concurrently through
`asyncio.gather()`. That's a different mechanism for reaching HTTP/2 multiplexed concurrency —
async coroutines instead of manually constructed frames on a single socket — but it gets requests
onto the wire close enough together to land inside the same race window, and it actually returned
responses.

## The Exploit

We pulled a fresh CSRF token and session cookie from `/login`, then built one `POST /login` request
per candidate password — thirty common passwords in total (`123456`, `password`, `12345678`,
`qwerty`, `123456789`, `12345`, `1234`, `111111`, `1234567`, `dragon`, `123123`, `baseball`,
`abc123`, `football`, `monkey`, `letmein`, `shadow`, `master`, `666666`, `qwertyuiop`, `123321`,
`mustang`, `1234567890`, `michael`, `654321`, `superman`, `1qaz2wsx`, `7777777`, `121212`,
`000000`), each carrying `csrf=TOKEN&username=carlos&password=CANDIDATE` and the same session
cookie, and fired all thirty simultaneously.

A correct login is distinguishable from every other outcome: it returns `302` with a `Location`
header pointing at `/my-account`, while wrong passwords return `200` with an "Incorrect password"
body and rate-limited attempts return `200` with a "too many" message. Out of the thirty concurrent
requests, only around four consistently landed inside the pre-lockout window before the counter
caught up — so the correct password had to be among those four to get a hit on any given burst.
When it wasn't, we re-ran the same batch (the race timing is probabilistic, not guaranteed), since
each burst effectively re-rolls which four candidates land in the window. Once a `302` response
turned up, we logged in as `carlos` with the password that produced it, opened `/admin`, and deleted
the `carlos` account to close out the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the same predict/benchmark/probe/prove structure: confirm the
per-username rate limit locks out after three sequential failed attempts, then show that sending
duplicate requests in parallel lets more than three land before the lockout applies. Their proof of
concept uses Turbo Intruder's bundled `race-single-packet-attack.py` template, queuing every
candidate password with `engine.queue(...)` behind a shared gate and firing them all at once with
`engine.openGate()` — Turbo Intruder's native single-packet attack primitive, run from inside Burp.

The underlying vulnerability and the exploitation logic are the same: exhaust a batch of guesses
inside one race window rather than one at a time. Where we differ is the delivery mechanism, and
for an interesting reason — our first attempt genuinely tried to match Turbo Intruder's single-packet
technique with a raw HTTP/2 socket implementation, and that specific approach failed against this
endpoint (no response to the connection preface), so we fell back to `httpx` with `asyncio.gather()`.
That's a real, if less precise, alternative path to the same concurrent-delivery goal: async
multiplexed requests over HTTP/2 aren't guaranteed to land in the exact same TCP packet the way
Turbo Intruder's engine does, but they land close enough together that the race window here was
still wide enough to catch.

## What This Teaches Us

The rate limit wasn't broken as a rule — three failed attempts genuinely does lock the account, if
those attempts arrive one after another. What broke is the assumption that "sequential" is the only
way requests arrive. Any security control implemented as read-then-increment rather than an atomic
counter operation has exactly this weakness, and login rate limiting is one of the highest-value
places for it to exist, because the entire point of the control disappears the moment concurrency
defeats it. The fix generalizes past this lab: enforce the attempt counter with an atomic increment
(or a lock held for the duration of the authentication check), so that no number of simultaneous
requests can ever all observe the same pre-increment state.
