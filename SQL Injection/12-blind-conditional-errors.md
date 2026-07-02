# Blind SQL injection with conditional errors

**Category:** SQL Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors

The previous lab had a convenient "Welcome back" message to key off. This one doesn't give us
anything that clean — no visible content difference between true and false at all. What it does
have is a database willing to throw an error on command, which turns out to be just as usable a
signal as any visible text.

## The Target

Once again the `TrackingId` cookie, this time against an Oracle backend, with no observable
difference in the page content between a query that succeeds and one that doesn't return matching
data — the response looks identical either way at the content level.

## The Investigation

With no content-based tell, we needed a signal that doesn't depend on what the page displays at
all. Oracle will throw a divide-by-zero error if forced to evaluate `1/0`, and critically, we can
make that evaluation *conditional* — wrapping it in a `CASE WHEN` so the error only fires when our
injected condition is true:

```
' AND (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE 'a' END FROM dual)='a'--
```

When the condition is true, the database attempts `1/0`, throws, and the application surfaces that
as an HTTP 500. When it's false, `TO_CHAR(1/0)` is never evaluated, the query completes normally,
and the response is a plain 200. That status-code difference — not any visible text — became our
oracle.

We confirmed the `users` table and the `administrator` row existed using the same conditional-error
wrapper before moving to extraction, exactly as we'd confirmed the true/false channel in the
previous lab.

## The Exploit

We applied the identical binary-search extraction strategy from the previous lab, but with the
signal swapped from "does the page say Welcome back" to "did this request return a 500":

```
' AND (SELECT CASE WHEN (SUBSTR(password,{pos},1) > 'X') THEN TO_CHAR(1/0) ELSE 'a' END
  FROM users WHERE username='administrator')='a'--
```

First we found the password length by incrementing a `LENGTH(password) = N` comparison inside the
same `CASE WHEN` wrapper until a 500 confirmed the match, then ran the character-by-character ASCII
binary search concurrently across all positions, same as before. The result was the administrator's
full password, used to log in and solve the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution builds the identical conditional-error primitive — confirming Oracle,
confirming the `users` table exists, then the `CASE WHEN ... THEN TO_CHAR(1/0) ELSE '' END`
construction to turn a boolean into an HTTP 500. Same trigger, same reasoning.

Extraction strategy is where this lab and the previous one tell the same story again: PortSwigger's
walkthrough runs Burp Intruder with an `a`–`z`/`0`–`9` payload list per character position,
identifying matches by response status code instead of grep-matched text this time, but still a
linear per-character alphabet search launched manually. We ran the same binary-search-plus-thread-pool
approach as the boolean lab, extracting the full password in a fraction of the requests and without
twenty separate manual Intruder launches.

## What This Teaches Us

This lab is the cleanest illustration in the whole series that "blind" doesn't mean "no signal" —
it means the signal has moved somewhere other than the response body. A status code the application
never intended to be meaningful (a 500 versus a 200) turned out to carry exactly as much information
as the visible "Welcome back" text from the previous lab, once we could trigger it conditionally.
Suppressing detailed error pages doesn't close this off, because the status code itself is the
leak, not its contents — the actual fix, as throughout this series, is removing the injection point
so no condition the attacker writes ever reaches the database's evaluator at all.
