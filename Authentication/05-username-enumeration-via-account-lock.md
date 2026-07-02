# Username enumeration via account lock

**Category:** Authentication
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-account-lock

Account lockout is supposed to be a defense. Here it doubles as an oracle: if only *real* accounts get locked out after repeated failures, the lockout message itself becomes a way to confirm which usernames exist — and if the lockout logic has its own gap, it can be turned into a way to brute-force the password of the account it just locked.

## The Target

The login form accepts repeated failed attempts, but per our verified notes, a valid username locks after enough wrong passwords and starts returning `You have made too many incorrect login attempts.` — a message an invalid username never produces, since it never gets far enough to trigger the lock.

## The Investigation

`detect_username_via_lock` in `Authentication.py` walks the username wordlist and, for each candidate, fires up to five wrong-password attempts in a row, checking each response for `too many` / `locked` / `block` text. The first username whose responses actually flip to that lockout language is confirmed valid — invalid usernames just keep returning the generic failure message no matter how many times they're hit.

That's stage one. Stage two is where this lab gets interesting: per our notes, the lock has a logic flaw — submitting the *correct* password while the account is still locked produces a response that's neither the lockout message nor a normal "incorrect password" error. It's just different, sometimes an empty or shorter body. `lab_7_username_enum_lock` captures a lockout baseline (length and text) using a fixed wrong password, then loops the 100-entry password list against the locked account, flagging any response that contains neither the lockout phrases nor `incorrect`/`invalid` — or that differs from the lockout baseline length by more than ten characters. That candidate is the real password, discovered *while the account is still locked and login is still blocked*.

## The Exploit

With a password identified through the lockout side channel, the script waited a full 60 seconds for the lockout window to expire, then performed a normal login with the recovered credentials. The tracker flipped to solved once the follow-up `/my-account` request confirmed the authenticated session.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution runs the same two-stage logic through two separate Intruder attacks. Stage one is a Cluster bomb attack: the username list against a Null-payload position generating five repeats per username, effectively hitting each candidate five times, then scanning for the longer response containing the lockout message. Stage two is a Sniper attack on the password parameter for the identified username, with a grep-extraction rule on the lockout error text — the one response with *no* extracted error at all (not even the lockout message) reveals the correct password, after which they wait a minute for the lock to clear and log in normally.

That's the same technique we used, structurally identical: trigger-and-detect the lock as the enumeration signal, then abuse the fact that a correct password still produces a distinguishable response even during lockout. The difference is purely mechanical — Cluster bomb plus grep-extract in the GUI versus two nested Python loops with string-matching logic doing the same detection.

## What This Teaches Us

This lab stacks two related mistakes. The first is familiar by now: a lockout message that only fires for real accounts is another username-enumeration oracle. The second is sharper — a lockout that's supposed to block *all* further authentication attempts against a locked account still leaks information (or, worse, still authenticates) when the correct password is submitted. A lockout implementation has to treat every attempt against a locked account identically, correct password or not, with no distinguishable response until the lock genuinely expires.
