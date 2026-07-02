# SQL injection attack, listing the database contents on Oracle

**Category:** SQL Injection
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle

Same objective as the previous lab — discover the schema from scratch and dump credentials through
it — but against Oracle, which keeps its schema metadata in its own dictionary views instead of
the ANSI-standard `information_schema`. The technique doesn't change; the system tables you point
it at do.

## The Target

The category-filter injection point again, this time confirmed Oracle (mandatory `FROM DUAL`,
as established two labs back), with an unknown schema to map.

## The Investigation

Oracle doesn't expose `information_schema` at all. In its place, Oracle maintains its own data
dictionary — `all_tables` for every table the current user can see, and `all_tab_columns` for
column definitions. The crawl is structurally identical to the non-Oracle version, just aimed at
different views:

**Step 1 — list tables:**

```
' UNION SELECT table_name, NULL FROM all_tables--
```

**Step 2 — list columns of the candidate credentials table:**

```
' UNION SELECT column_name, NULL FROM all_tab_columns WHERE table_name='<USERS_TABLE>'--
```

One easy-to-miss detail: Oracle identifiers are stored upper-case by default unless the table was
created with a quoted mixed-case name. Filtering `all_tab_columns` by `table_name='users_abcdef'`
in lower case silently returns nothing — the filter has to match the stored case, which in
practice means upper-casing whatever table name you pulled out of `all_tables` before using it in
the next query.

## The Exploit

With the real (upper-cased) table and column names confirmed, the final extraction is the same
shape as every other UNION credential dump in this series:

```
' UNION SELECT <USERNAME_COL>, <PASSWORD_COL> FROM <USERS_TABLE>--
```

The response listed every account, including `administrator`, with its password in plaintext. We
logged in with that password through the normal login form, which the lab tracker registered as
the solve condition.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the identical path: `all_tables` to find the credentials table,
`all_tab_columns` filtered by that table name (explicitly upper-cased in their payload, e.g.
`'USERS_ABCDEF'`) to find the username and password columns, then a final `UNION SELECT` on those
two columns from the discovered table. Same dictionary views, same case-sensitivity handling, same
final query shape.

As with the non-Oracle version of this lab, the real difference is that our version ran through a
generic enumeration routine (with an `oracle=True` flag that swaps `information_schema` for
`all_tables`/`all_tab_columns` and applies the upper-casing automatically) rather than three
separate manually-read Repeater requests. The underlying SQL is the same in both cases.

## What This Teaches Us

Oracle's dictionary views make the same point as `information_schema` does on other engines, with
an extra wrinkle: even database-specific "obscurity" — different table names, different metadata
views, case-sensitivity quirks — doesn't slow an automated or determined attacker down much, it
just changes which system view gets queried first. The fix doesn't change either: parameterized
queries stop the `category` parameter from ever being anything other than a literal string, which
means `all_tables` and `all_tab_columns` are never reachable through this endpoint regardless of
how the schema itself is named or cased.
