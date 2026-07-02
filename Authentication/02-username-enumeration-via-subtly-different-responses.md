# Username enumeration via subtly different responses

**Category:** Authentication
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-subtly-different-responses

Developers who patch the "obvious" username enumeration bug usually do it by unifying the error message text — and then ship a version with a stray character difference between the two code paths that generate it. This lab is built around exactly that near-miss: the message is supposed to be identical either way, and it almost is.

## The Target

Same `POST /login` shape as before, but this time the error text for an invalid username and the error text for a valid username with the wrong password are meant to read as one unified message: `Invalid username or password`. Whether the application actually manages that consistently is the question.

## The Investigation

Our `lab_4_username_enum_subtle` wrapper started the same way as the previous lab: capture a baseline response for a known-bad username, but this time extract just the error text itself with a regex targeting the error/warning CSS classes, rather than diffing the whole page. That matters here — comparing full response bytes would catch *any* incidental difference (session tokens, CSRF values embedded elsewhere on the page), while extracting only the rendered error message isolates the one field that's supposed to be identical.

Walking the username wordlist and comparing each extracted message against the baseline, one entry produced a message that didn't match character-for-character. Per our verified notes, the specific difference we caught was a missing trailing period at the end of the message compared to the baseline's `Invalid username or password.` — a one-character discrepancy invisible at a glance but exact in a string comparison. As a fallback, in case no message-level diff surfaced, the script also compared raw response length across the full page, in case the discrepancy showed up somewhere the regex didn't reach.

## The Exploit

With the subtly-different response flagged as the valid username, the second stage was the same password brute-force loop as the previous lab: iterate the 100-entry password list against the identified username, fresh CSRF per request, watching for a `302` redirect to confirm the correct password. Once found, logging in and loading `/my-account` flipped the lab's tracker.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's own solution targets the same idea but documents a different specific character defect: their walkthrough describes the anomalous response as containing **a trailing space** instead of the period, caught using Burp Intruder's "Grep - Extract" rule against the literal string `Invalid username or password.` and then eyeballing which extracted value differed. Ours caught a missing trailing period rather than an added trailing space — a different exact byte, but the same class of bug: a one-character typo in an error message that was supposed to be byte-for-byte uniform between the two failure paths.

That divergence is worth taking at face value rather than smoothing over — it's a good illustration of the underlying lesson: this bug class isn't about *which* character differs, it's about the fact that any character differs at all between two responses that are supposed to be indistinguishable. Whether Burp's grep-extract flags a missing period or our regex-based diff flags a missing period, both are catching the same root defect from different angles. The password-brute-force stage that follows is identical between the two approaches — Intruder Sniper with a `302` filter versus our scripted loop.

## What This Teaches Us

"We fixed username enumeration by making the error messages the same" is a common but fragile claim — it only holds if the two code paths that generate that message are byte-for-byte identical, including whitespace and punctuation. A single stray space or missing period, introduced by something as mundane as two slightly different string templates in the codebase, reopens the exact vulnerability the fix was meant to close. Verifying a fix like this means diffing raw response bytes, not reading the message and nodding along.
