# Visible error-based SQL injection

**Category:** SQL Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/sql-injection/blind/lab-sql-injection-visible-error-based

The two previous labs treated database errors as a one-bit signal — did the request 500 or not.
This lab is a step further: the application's error page doesn't just fail on bad input, it prints
the underlying database error message directly into the response, which turns error-based
injection from a blind oracle into a direct read primitive.

## The Target

The `TrackingId` cookie again, on a backend that returns verbose error details in the HTTP response
whenever the injected SQL is malformed — rather than a generic error page.

## The Investigation

Sending a single quote in the cookie immediately confirmed this: the response came back with a
detailed database error describing the exact syntax problem, including a fragment of the query
itself. That's already more than a boolean channel — it's a channel that will print *whatever text
we can coerce the database into including in an error message*.

The classic way to weaponize that is a type-cast failure: forcing the database to `CAST` a string
value to an integer. The cast fails, and — critically — many databases include the *offending
value itself* in the resulting error text:

```
' AND 1=CAST((SELECT username FROM users) AS int)--
```

Two practical snags came up putting this into practice. First, the cookie has a length limit
around 63 characters, and the original `TrackingId` prefix was eating into that budget — we
resolved it by injecting with an *empty* tracking ID rather than appending after the original
value, since the query still evaluates correctly against an empty string. Second, `SELECT username
FROM users` on its own returns every row, and the cast fails on the *first* row the database
happens to evaluate — which raised a "more than one row returned by a subquery" error instead of
the value we wanted, until we added `LIMIT 1` to force a single row.

## The Exploit

With both issues resolved, the working payload was:

```
TrackingId=' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--
```

The error response included the offending username value directly in its text — we parsed it out
with a pattern matching the database's own error format (PostgreSQL's
`invalid input syntax for type integer: "<value>"` is the shape our extraction regex targets).
Swapping `username` for `password` in the same query — `(SELECT password FROM users LIMIT 1)` —
pulled a password out the same way, with no `WHERE` clause needed: this lab's `users` table
returns the account we need on that same unfiltered first row, so the two single-column casts line
up as the same account. We logged in with the extracted password to solve the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the identical discovery arc: a bare `'` triggers a verbose error,
appending `--` clears it, the `CAST` trick then produces a type-mismatch error containing the cast
value, and the same two snags appear in their walkthrough too — truncation on the original cookie
value (solved by deleting the original prefix, same fix we used) and a multi-row error (solved with
`LIMIT 1`, same fix). This is one of the more procedurally identical labs in the series: same
payload, same two gotchas, same resolution for each.

The difference is, again, extraction mechanics rather than technique — PortSwigger reads the
username and password directly out of the rendered error page by eye; we parsed the same error
text with a regex tuned to the specific error format the database returns, which matters more once
this same primitive gets reused at scale than it does for a single extraction.

## What This Teaches Us

Verbose error messages are a genuine, often underestimated data-exfiltration channel — not just a
"does this fail" signal like the previous two labs, but a way to make the database narrate its own
data back to you inside an error string. It's also a lab about the small implementation details
that separate "confirmed vulnerability" from "successful extraction" — the cookie length limit and
the multi-row subquery error weren't part of the core SQL injection at all, but without handling
both, the technique doesn't produce usable output. Turning off detailed error messages in
production is real, valuable defense-in-depth here — but as with every lab in this series, it's a
mitigation, not a fix; the actual fix is removing the injection point so the database is never
asked to evaluate attacker-authored conditions at all.
