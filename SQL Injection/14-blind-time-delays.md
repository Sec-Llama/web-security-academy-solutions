# Blind SQL injection with time delays

**Category:** SQL Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/sql-injection/blind/lab-time-delays

Every blind technique so far in this series has needed the response to differ somehow — a
message, a status code, an error string. This lab removes even that: the response is completely
identical whether the injected condition is true or false. The only thing left to measure is how
long the database takes to answer.

## The Target

The `TrackingId` cookie once more, this time on a PostgreSQL backend configured so that the
response content, status code, and length are all indistinguishable regardless of what SQL gets
injected — the only observable dimension left is timing.

## The Investigation

PostgreSQL's `pg_sleep(seconds)` function does exactly what it says: pauses query execution for a
given duration and returns nothing meaningful otherwise. Injected into the query, it turns "is this
condition true" into "does the response take N seconds longer than normal" — no visible difference
required at all, just a stopwatch.

The lab doesn't ask for data extraction, only confirmation that the injection can control execution
time — which makes it the right place in this series to establish the technique in isolation before
combining it with character extraction in the next lab.

## The Exploit

We appended a delay directly onto the cookie value:

```
TrackingId=x'||pg_sleep(10)--
```

The baseline request returned in well under a second; this one took roughly ten seconds to
complete. That measured delay — not any content difference — was the confirmation the lab was
looking for, and the lab tracker flipped to solved on that response alone.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution uses the identical payload and reasoning: intercept the `TrackingId`
cookie, set it to `x'||pg_sleep(10)--`, and observe the ten-second delay. There's no divergence in
technique at all for this lab — it's a single payload with an unambiguous, directly measurable
result.

The only difference is that their walkthrough forwards the modified request once through Burp's
proxy and watches the response time in Burp's UI; we sent it as a scripted request and measured the
elapsed time programmatically. Same payload, same outcome, different stopwatch.

## What This Teaches Us

Time-based blind injection matters because it's the fallback that works even when every other
observable channel — content, length, status code — has been made identical by the application.
It's also the noisiest and slowest technique in this series: every bit of information costs a
multi-second wait, which is exactly why the next lab in this series, extracting real data through
timing, needs a smarter extraction strategy than brute-force alphabet testing to be practical at
all. The fix is unchanged: a parameterized `TrackingId` value never reaches the SQL parser as
executable syntax, so there's no `pg_sleep` call for an attacker to trigger regardless of how
patient they're willing to be.
