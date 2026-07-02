# SQL injection attack, querying the database type and version on MySQL and Microsoft

**Category:** SQL Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft

Where the previous lab fingerprinted an Oracle backend, this one covers the pair of database
engines that dominate most real-world applications: MySQL and Microsoft SQL Server. They share
enough syntax that the same version-fingerprinting payload works against both, which is worth
knowing precisely because it means you don't always need to know exactly what you're attacking
before you attack it.

## The Target

The same category-filter injection point as always, this time backed by either MySQL or MSSQL —
the lab doesn't announce which, and part of the exercise is that it doesn't need to.

## The Investigation

We repeated the same two-step UNION groundwork as before: increment `NULL` columns until the
query stops erroring to get the column count, then swap in a marker string per position to find
which column renders as text in the response.

The one difference from the Oracle case is syntactic. Neither MySQL nor MSSQL requires a `FROM`
clause for a query that isn't reading from a real table — `SELECT NULL` is valid on its own in
both engines, unlike Oracle's mandatory `FROM DUAL`. That single difference is often enough to
tell you, before you've even fingerprinted the version, that you're not talking to Oracle.

## The Exploit

Both MySQL and MSSQL expose the running version through the same built-in variable, `@@version`,
which made the extraction payload identical for either engine:

```
' UNION SELECT @@version, NULL--
```

The response returned the database's full version banner in the text-bearing column position —
on MySQL this reads as a MySQL version string, on MSSQL as a SQL Server build string, which is
itself the confirmation of which engine we're actually talking to.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's walkthrough uses the identical `@@version` variable, arriving at
`'+UNION+SELECT+@@version,+NULL#` after the same column-count and text-column confirmation step
(`'+UNION+SELECT+'abc','def'#`). Note their payload uses `#` as the comment terminator rather than
`--` — both are valid MySQL comment syntax, and either works; we used `--` (with the trailing
space MySQL requires, or `#`, per the payload — the DB-specific comment table in our own notes
tracks `-- ` for MySQL and `#` interchangeably).

Technique-wise there's no divergence at all here — same variable, same UNION structure. The only
difference remains the delivery mechanism already noted in the previous two labs: manual
Repeater edits versus a scripted request.

## What This Teaches Us

`@@version` (MySQL/MSSQL) and `v$version`/`banner` (Oracle) are the kind of database-native
metadata that's genuinely useful to an attacker and genuinely invisible to an application's own
input validation — nothing about a `category` filter suggests it should ever be able to return
server version information. That mismatch is the whole story of SQL injection: the vulnerability
isn't in the version variable, it's in a query that lets attacker input decide what gets selected
at all. Parameterized queries remove the possibility outright, regardless of which database engine
sits behind them.
