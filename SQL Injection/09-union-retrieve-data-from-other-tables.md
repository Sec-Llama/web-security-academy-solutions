# SQL injection UNION attack, retrieving data from other tables

**Category:** SQL Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables

This lab puts the two previous ones together for the first time: known column count, known
text-bearing column, and — unlike the schema-discovery labs — a known table and column structure
handed to us up front (`users`, with `username` and `password` columns). It's the most direct
version of "column count plus text column equals arbitrary data exfiltration" in the whole series.

## The Target

The category filter, injectable, with a `users` table known to exist in the schema — the lab tells
us the table and column names directly, removing the `information_schema` discovery step so the
UNION mechanics themselves are the whole focus.

## The Investigation

With the table structure already known, there's nothing left to discover except the two facts
every UNION attack in this series needs first: the column count of the original query, and which
of those columns renders text. We confirmed both exactly as in the two previous labs — incrementing
`NULL`s until the error cleared, then substituting a marker string per position.

The only new decision is that a UNION `SELECT` can pull from a completely different table than the
one the original query targets — `products` and `users` don't need to be related in any way for
this to work. The database doesn't care that the two halves of a `UNION` come from unrelated
tables; it only cares that the column count and types line up.

## The Exploit

With two known text columns available (positions confirmed empty vs. text-bearing exactly as in
lab 8), we selected both credential columns directly from `users`:

```
' UNION SELECT username, password FROM users--
```

The response rendered the full contents of the `users` table inline in the product listing —
every username paired with its plaintext password, including `administrator`. Logging in with
that password against the normal login form was the lab's solve condition.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution runs the identical sequence: confirm two text columns with
`'+UNION+SELECT+'abc','def'--`, then extract directly with
`'+UNION+SELECT+username,+password+FROM+users--`. Same table, same columns, same single-request
extraction — there's no meaningful technique difference at all in this lab.

The only distinction, again, is that PortSwigger's walkthrough is a manual Repeater edit while ours
ran as a scripted request once the column count and text position were confirmed — the confirmation
steps themselves were handled by the same generic column-detection routine used throughout this
series.

## What This Teaches Us

This is the lab that makes UNION injection's real danger obvious without any obfuscation in the
way: once an attacker controls a `SELECT`'s column list, the query's original table is essentially
irrelevant — any table the database user can read becomes reachable through that one injection
point, credentials table included. It's a strong argument for least-privilege database accounts on
top of parameterized queries: even if a query were somehow still vulnerable, a database user with
no read access to a `users` table couldn't leak it through this channel.
