# SQL injection attack, listing the database contents on non-Oracle databases

**Category:** SQL Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle

Fingerprinting a database is reconnaissance. This lab is where UNION-based SQL injection turns
into an actual data breach: instead of pulling a version string out of a system variable, we map
the schema itself and pull real user credentials out of it — starting from zero knowledge of what
tables even exist.

## The Target

The familiar `category` filter, this time on a non-Oracle backend where we don't yet know the
schema at all — no table names, no column names, nothing beyond "there's probably a users table
somewhere."

## The Investigation

Every non-Oracle SQL database exposes its own schema through `information_schema`, a standard set
of views that describe every table and column in the database — and crucially, `information_schema`
is itself queryable through the same UNION injection we already have working. That means the
injection point can be used to ask the database to describe itself before we ask it for any real
data.

After confirming the column count and text-column position exactly as in the previous two labs,
we queried the schema in two steps:

**Step 1 — list every table:**

```
' UNION SELECT table_name, NULL FROM information_schema.tables--
```

This returned every table in the database, including the lab's randomized-name credentials table
(PortSwigger obfuscates the real table name per lab instance specifically so it can't be guessed —
you have to discover it).

**Step 2 — list the columns of the candidate table**, once we picked out the one that looked like
a user store:

```
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='<users_table>'--
```

This gave us the column names — again randomized, but recognizable as username- and
password-shaped once listed.

## The Exploit

With the real table and column names in hand, we ran a final UNION query selecting both credential
columns directly:

```
' UNION SELECT <username_col>, <password_col> FROM <users_table>--
```

The response listed every account's username and password in plaintext, including an
`administrator` row. We took that password and logged in through the normal login form — the lab
tracker confirmed as solved on that authenticated session.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution walks the exact same three-stage schema crawl: `information_schema.tables`
to find the credentials table, `information_schema.columns` filtered by that table name to find
the username/password columns, then a final `UNION SELECT` on those two columns. Same views, same
order of operations, same outcome.

The meaningful difference here is genuinely about automation rather than just delivery. Their
walkthrough is three separate manual Repeater requests, each one read by a person to decide what
to query next. We ran this through a generic `enumerate_tables` → `enumerate_columns` →
credential-dump pipeline that does the same three queries but picks the next step programmatically
— it looks for a table name containing `user` and a column name containing `user`/`pass`, the same
heuristic a person applies by eye when scanning a table list. The SQL sent to the database is
identical in substance; only who decided what to query next differs.

## What This Teaches Us

`information_schema` exists so database tooling can introspect a schema — it was never meant to be
reachable by an unauthenticated request through a product filter, and yet any injection point that
supports UNION gets it for free. This is the lab that makes clear why "the attacker doesn't know
our table names" is not a defense: the schema itself is queryable through the same channel as the
data. Parameterized queries are the fix, as always — but it's worth noting that least-privilege
database accounts are a real second layer here too: a web application's DB user genuinely doesn't
need `SELECT` rights on `information_schema` or on tables it never touches directly, and revoking
that access would have blocked this specific escalation even if the injection point still existed.
