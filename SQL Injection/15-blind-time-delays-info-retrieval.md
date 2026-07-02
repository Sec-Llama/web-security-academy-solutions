# Blind SQL injection with time delays and information retrieval

**Category:** SQL Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval

The previous lab proved timing alone can carry a signal. This one turns that signal into full
data extraction — the same conditional binary-search approach from the boolean and error-based
labs earlier in this series, except every single comparison now costs a real wait instead of a
free response read.

## The Target

The `TrackingId` cookie, PostgreSQL backend, identical responses regardless of the injected
condition's truth value — same constraint as the previous lab, but this time we need the
administrator's actual password out of it, not just a timing confirmation.

## The Investigation

The direct approach — `'; SELECT pg_sleep(10)--` as a stacked second statement — didn't fire the
way it does in some other database drivers: the PostgreSQL driver behind this lab has multi-statement
execution disabled, so a literal stacked `pg_sleep` call after a semicolon never actually runs.

The fix is to force the delay to happen *inside* the original single statement instead of as a
second one, using a conditional subquery wrapped so its result has to be evaluated:

```
' AND (SELECT CASE WHEN (<condition>) THEN pg_sleep({delay}) ELSE pg_sleep(0) END
  FROM users WHERE username='administrator') IS NULL--
```

The `IS NULL` check at the end isn't testing anything meaningful about the data — `pg_sleep()`
always returns a value, so the comparison is always true. Its real purpose is forcing PostgreSQL to
actually evaluate the subquery in order to answer the `IS NULL` question, rather than potentially
short-circuiting it away. Without that forcing mechanism, the conditional delay simply doesn't run
in this driver configuration.

There's a second constraint layered on top of the first: the same cookie-length limit encountered
in the visible-error lab applies here too. We used the same fix — an empty `TrackingId` prefix
rather than appending after the original value — to keep the payload inside the length budget.

## The Exploit

With the delay-forcing pattern confirmed, we ran the same length-then-character binary search
established in the boolean-blind lab, just with "true" now meaning "this request took roughly
`delay` seconds longer than baseline" instead of a content or status difference:

```
' AND (SELECT CASE WHEN (ASCII(SUBSTRING(password,{pos},1))>{mid}) THEN pg_sleep({delay})
  ELSE pg_sleep(0) END FROM users WHERE username='administrator') IS NULL--
```

Unlike the boolean and error-based extractions earlier in this series, this one had to run
strictly sequentially — firing the same timing probe concurrently across multiple character
positions would make every in-flight request's elapsed time unreliable, since server load and
network jitter get much harder to distinguish from a genuine `pg_sleep` once several timed
requests are in flight at once. We used a short two-second delay per comparison rather than the
full ten seconds, which is enough margin to reliably distinguish a real delay from network noise
while keeping the total sequential extraction time reasonable. The recovered string was the
administrator's password, used to log in and solve the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution uses the same `CASE WHEN ... THEN pg_sleep(10) ELSE pg_sleep(0) END`
construction, confirms the administrator account and password length the same way, then moves
extraction into Burp Intruder with a `§a§`-marked payload position and an `a`–`z`/`0`–`9` payload
list — explicitly setting Intruder's resource pool to a maximum of one concurrent request, for the
same reason we ran ours sequentially: concurrent timing requests corrupt each other's measurements.
That single detail — both approaches independently landing on "this one has to be sequential" — is
the strongest confirmation that the constraint is real and not an artifact of either tooling
choice.

The difference is the same one that's run through this whole series: their extraction is a manual,
alphabet-based Intruder attack per character position; ours is a scripted binary search. Both
respect the same sequential-only constraint this lab specifically imposes.

## What This Teaches Us

This lab is a good demonstration that "blocked" isn't the same as "fixed" — disabling stacked
queries closed off the most obvious time-based payload, but the underlying injection point was
still fully exploitable once the delay moved inside a single statement instead of a second one.
It's also the one technique in this entire series where automation's usual advantage (concurrency)
actively works against you: the same timing signal that makes the attack possible also makes it the
one place where going faster by going parallel breaks the measurement itself. As always, the actual
fix isn't in how the driver handles stacked queries — it's parameterizing the `TrackingId` value so
no conditional expression, timed or otherwise, ever reaches the database as executable SQL.
