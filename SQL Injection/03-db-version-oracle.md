# SQL injection attack, querying the database type and version on Oracle

**Category:** SQL Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle

Once you can inject into a query, the next question an attacker actually asks is rarely "can I
see one more row" — it's "what am I even talking to." Database fingerprinting matters because
every dialect of SQL has its own syntax quirks, comment styles, and system tables, and getting it
wrong wastes every subsequent payload. This lab is about answering that question using the
technique that everything downstream in this series builds on: the UNION attack.

## The Target

Same shape of vulnerable endpoint as before — a `category` filter on a product listing page,
concatenated into a query. This time the backing database is Oracle, which behaves differently
from MySQL or PostgreSQL in ways that matter the moment you try to run a UNION query against it.

## The Investigation

A `UNION SELECT` attack lets an attacker append an entirely separate query's results onto the
original one, but only if two conditions are met: the injected `SELECT` returns the same number
of columns as the original query, and each column's data type is compatible with what the
original query returns in that position. So before extracting anything, we have to work both of
those out.

**Finding the column count.** Injecting `NULL` values one at a time is the standard method — `NULL`
is compatible with virtually every column type, so the query only fails while the count is wrong:

```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
```

We kept adding a `NULL` until the response stopped erroring, which told us how many columns the
original query returns.

**Finding which columns accept text.** With the count known, we replaced each `NULL` in turn with
a marker string and checked which position it survived in without an error — that position
accepts text data and is where we can later place extracted strings.

**The Oracle-specific catch.** Oracle doesn't allow a bare `SELECT` without a `FROM` clause — every
query needs a table to select from, even when you're not actually selecting real table data. The
convention is `FROM DUAL`, a built-in one-row table that exists specifically for this. Without it,
every UNION attempt against an Oracle backend fails with a syntax error that has nothing to do
with the column count or types — which is a trap if you don't already know to expect it.

## The Exploit

With the column count and string-column position confirmed, we queried Oracle's version banner
directly from its system view:

```
' UNION SELECT banner, NULL FROM v$version--
```

`v$version` is an Oracle system view containing version and build information for the database
instance. The response returned the Oracle version string in place of a normal product listing,
in the position we'd already confirmed accepted text.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the same two-stage process: first confirm the column count and text
column with `'+UNION+SELECT+'abc','def'+FROM+dual--`, then query the version with
`'+UNION+SELECT+BANNER,+NULL+FROM+v$version--`. Same system view, same `FROM DUAL` requirement,
same reasoning throughout.

The difference is again mechanical rather than technical: their walkthrough determines the column
count and text position manually, one Burp Repeater request at a time. We used a generic
column-detection routine that automates exactly that same NULL-incrementing and marker-string
process — same requests, same logic, just driven by a script instead of a person clicking
"Send" repeatedly.

## What This Teaches Us

UNION-based extraction only works because the database has no way to tell "a legitimate second
part of this query" apart from "an attacker-appended query" — it just executes whatever SQL text
it's handed. The Oracle-specific `FROM DUAL` requirement is a good reminder that generic SQL
injection payloads aren't actually generic; database fingerprinting isn't a side quest, it's a
prerequisite for every attack that comes after it. As always, the actual fix is the same one that
closes every lab in this series: parameterized queries mean the database never sees `category` as
anything other than a single opaque value, and there's no query text left for a UNION clause to
attach to.
