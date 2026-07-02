# Username enumeration via response timing

**Category:** Authentication
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing

Once a message-based leak is closed, timing is the next place account existence hides. If the server only bothers to hash the submitted password when the username is real — because there's no point comparing a password hash against an account that doesn't exist — then every valid username costs measurably more server time than an invalid one, no matter how identical the two responses look.

## The Target

The same `POST /login` endpoint, now with uniform error text regardless of username validity. What's not uniform is the backend work: a valid username triggers a bcrypt comparison against the stored hash, and bcrypt is deliberately slow. An invalid username short-circuits before that comparison ever happens.

## The Investigation

Timing side channels are noisy over a real network, so the design our `Authentication.py` uses (`detect_username_via_timing` / `lab_5_username_enum_timing`) leans on two amplifiers before trusting any single measurement. First, per our verified notes, we sent a 500-character password on every attempt — far longer than strictly necessary, but a longer input makes the bcrypt comparison itself take measurably longer for valid accounts, widening the timing gap we're trying to detect. Second, every single request carried a unique `X-Forwarded-For` header, spoofing a fresh source IP, so the app's own rate limiting couldn't slow down (or flag) our repeated probing of the same endpoint.

Rather than trusting one sweep across the username list, the lab wrapper ran three full passes over all candidate usernames, recording elapsed time for each `POST /login` and averaging per-username timing across all three passes at the end. The username with the highest average time relative to the overall average — specifically, a ratio above 1.5x the mean — was flagged as the likely valid account; if nothing cleared that bar, the script fell back to whichever username scored highest regardless, since network jitter can still suppress the signal on a given run.

## The Exploit

Password brute-forcing then ran the same way as the earlier labs, again spoofing a unique `X-Forwarded-For` per request to avoid triggering brute-force protection, iterating the 100-entry password list against the timing-identified username until a `302` redirect (or a response with no error text, confirmed via `/my-account`) revealed the correct password.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution uses the same underlying signal — bcrypt-driven timing difference amplified with a long password and IP spoofing to dodge brute-force protection — but drives it through a single Burp Intruder Pitchfork attack: payload position one cycles through numbers 1–100 to generate the spoofed `X-Forwarded-For` values, payload position two cycles through the candidate usernames, and the password field carries one fixed ~100-character string for the whole attack. Response timing is read straight off Intruder's "Response received"/"Response completed" columns in a single pass.

Our approach differs in two concrete ways worth naming: we used a 500-character password rather than ~100 characters for a stronger timing signal, and we ran three complete passes over the username list with statistical averaging rather than trusting one pass's raw numbers. Both are answers to the same problem — timing measurements over a real network are noisy — just solved differently: PortSwigger's manual walkthrough relies on a human eyeballing the Intruder results table for an outlier in one pass, while our script quantified "outlier" numerically and repeated the measurement to filter jitter before trusting it.

## What This Teaches Us

Removing a content-based leak doesn't remove a timing-based one if the backend still does asymmetric work — hashing a password only for accounts that exist is a completely reasonable-sounding optimization that happens to be a side channel. The real fix is constant-time behavior regardless of username validity: either hash a dummy password for nonexistent accounts too, or use a fixed artificial delay so the total request time doesn't depend on which branch executed. This lab is also a reminder that averaging over repeated measurements, not a single timestamp, is what makes a timing attack reliable outside a lab's controlled network conditions.
