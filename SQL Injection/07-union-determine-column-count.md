# SQL injection UNION attack, determining the number of columns returned by the query

**Category:** SQL Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns

Every UNION-based attack in this series depends on one piece of information that isn't visible
anywhere in the application: how many columns the original query actually selects. This lab
isolates that single step, which is worth doing in isolation once, because getting it wrong
quietly breaks every later stage of a UNION attack without necessarily producing an obvious error.

## The Target

The usual `category` filter, injectable, backing a query whose column count is deliberately
unknown to us going in.

## The Investigation

There are two standard ways to find a UNION query's column count, and we used the more direct of
the two: incrementing `NULL` columns in a `UNION SELECT` until the database stops complaining. The
alternative — `ORDER BY` with an increasing column index until it errors — works by a different
mechanism (referencing a column position that doesn't exist) but reaches the same number; we
documented both approaches, but the `UNION SELECT NULL[,NULL...]` method is what we ran here.

`NULL` is the right probe value because it's implicitly compatible with almost every SQL data
type — a `NULL` in an integer column and a `NULL` in a varchar column both type-check, so failures
at this stage are reliably about column *count*, not column *type*.

## The Exploit

We sent an increasing sequence of `UNION SELECT` payloads against the `category` parameter:

```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

Each attempt with too few columns returned a database error, because a `UNION` requires both sides
to return the same number of columns as the original query. The moment the column count matched,
the error disappeared and the response rendered normally — with the injected `NULL` row folded
invisibly into the product listing, confirming the correct count.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution runs precisely this sequence — starting from `'+UNION+SELECT+NULL--`,
observing the error, and adding one more `NULL` at a time until "the error disappears and the
response includes additional content containing the null values." Identical method, identical
reasoning.

The only difference is that their walkthrough re-sends each attempt by hand through Burp Repeater,
watching the response after every click, while we ran the same incrementing sequence through a
short loop that stops at the first non-error response. Same requests, same order, automated
instead of manual.

## What This Teaches Us

Column-count discovery looks like a technicality, but it's the load-bearing step underneath every
UNION attack that follows in this series — get it wrong and every subsequent extraction payload
fails with a confusing error that has nothing to do with the actual data you're trying to pull.
It's also a clean illustration of how much information a database error message alone leaks: the
application never intended to expose its column count, but the mere presence or absence of an
error, with no error text needed at all, was enough to derive it. Suppressing detailed database
errors reduces the *verbosity* of that leak but doesn't close it — the binary
error/no-error signal survives even a generic 500 page, which is why the real fix is still
preventing the injection in the first place, not just quieting its error output.
