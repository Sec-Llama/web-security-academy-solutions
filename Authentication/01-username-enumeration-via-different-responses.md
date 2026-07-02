# Username enumeration via different responses

**Category:** Authentication
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses

A login form only needs to say one thing to an attacker: "wrong." The moment it says two different kinds of wrong — one for a username that doesn't exist, another for a username that does but paired with the wrong password — it has quietly split the entire credential-guessing problem into two much smaller ones. This lab is the cleanest version of that leak: the difference sits right there in the response body, no timing analysis or lockout side effects required.

## The Target

The login form is a standard `POST /login` with `username` and `password` fields. A wrong guess against a nonexistent account and a wrong guess against a real account both come back as failures — the question is whether the application phrases those two failures identically.

## The Investigation

We ran this through `Authentication.py`'s `lab_1_username_enum_response` wrapper rather than working it in Burp's GUI. The first step was establishing a clean baseline: a request with a username we knew couldn't exist (`invalid_user_xyz`) and a throwaway password, capturing the exact response text, length, and status code.

From there the script walked our 101-entry candidate username wordlist (`auth_usernames.txt`), resending the same throwaway password against each one and diffing every response against that baseline — both the raw text and the status code. Per our verified notes, the two error strings the app actually uses are `"Invalid username"` for a username that doesn't exist and `"Incorrect password"` for one that does, a difference of only a couple of characters in response length. That's a small enough delta that eyeballing it would be easy to miss on a single request, but comparing full response bytes programmatically against a fixed baseline catches it immediately — the first username whose response text or status diverged from the baseline was the hit.

## The Exploit

With a confirmed valid username in hand, the same script immediately pivoted to brute-forcing the password: looping through the 100-entry candidate password list (`auth_passwords.txt`), resubmitting `username=<found>&password=<candidate>` on a fresh CSRF token each time, and watching for either a `302` redirect or a response body that no longer contained `incorrect`/`invalid` — followed by a confirmation `GET /my-account` to verify the session was actually authenticated. The first password that produced a real redirect to `/my-account` was the correct one, and the lab's solve tracker flipped immediately after.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's published solution runs the identical two-stage logic through Burp Intruder: a Sniper attack on the `username` parameter with the candidate list, sorted by the **Length** column to spot the one entry whose response text says "Incorrect password" instead of "Invalid username" — then a second Sniper attack on `password` for that username, filtering for the `302` response. That's exactly the baseline-diff-then-brute-force shape our script follows.

The only real difference is delivery: PortSwigger drives both Intruder passes by hand through the GUI, reading the Length column and the status code column visually. We ran the same two passes as two nested loops in Python, diffing raw response bytes against a captured baseline instead of reading a sorted table. For a two-stage attack like this one, both approaches converge on the same requests — scripting mainly saves the manual column-sorting step.

## What This Teaches Us

The vulnerability isn't in the password check at all — it's that the *first* check (does this username exist) and the *second* check (does the password match) produce observably different failure text. Any attacker with a username wordlist can now separate "invalid account" from "valid account, wrong password" and only spend brute-force effort on the accounts that are real. The fix is uniform: identical wording, identical length, identical status code, and ideally identical response timing, regardless of which check actually failed.
