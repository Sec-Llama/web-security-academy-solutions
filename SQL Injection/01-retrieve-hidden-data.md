# SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

**Category:** SQL Injection
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data

SQL injection has been on the OWASP Top 10 for over two decades, and it survives not because
developers don't know it exists, but because of exactly the pattern this lab demonstrates: a
filter that looks completely safe from the outside, backed by a query that concatenates
user input directly into a `WHERE` clause. This is the simplest possible version of that mistake,
and it's the right place to start because every other SQL injection technique in this series is
a variation on the same idea — find where your input lands inside the query, then change the
query's logic instead of just its data.

## The Target

The lab is a small e-commerce storefront. Browsing a product category sends a GET request like:

```
GET /filter?category=Gifts
```

The response lists every product in the `Gifts` category. Critically, the store also has products
that exist in the database but are marked unreleased — they're excluded from every category page
a normal visitor sees. That exclusion is enforced by the application appending an extra condition
onto the query used to build the category page.

## The Investigation

Nothing about the `category` parameter suggests injection at first glance — it just picks a
filter value. But "the query has an invisible extra condition" is exactly the shape of bug this
lab is testing for. If the backend query looks like:

```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

then closing the string early and adding our own condition lets us override the intent of that
second clause entirely, not just the first one. We don't need to know the column name (`released`)
or its exact value — we just need a condition that's true regardless of what follows it.

## The Exploit

We sent the category value with a classic tautology appended, closing the original string and
commenting out whatever the application concatenates after it:

```
GET /filter?category=Gifts' OR 1=1--
```

Which turns the query into:

```sql
SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
```

The `--` comments out the trailing `AND released = 1`, and `1=1` is unconditionally true, so the
`WHERE` clause now matches every row in the table regardless of category or release status. The
response came back containing products that never appear on any normal category page — proof the
hidden, unreleased rows were now part of the result set.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's published solution reaches the identical payload: intercept the category request in
Burp Suite, and change the `category` value to `'+OR+1=1--` (URL-encoded form of the same string).
The mechanism they describe — closing the quoted string, injecting `OR 1=1`, and commenting out
the rest of the query — is exactly the reasoning above.

The only real difference is delivery. PortSwigger's walkthrough is manual: intercept the request
in Burp's proxy, edit the parameter by hand, forward it. We ran the same payload through a small
Python script against the `/filter` endpoint directly, which is really just automating the same
single HTTP request rather than editing it through a proxy GUI. For a one-shot payload like this
one, manual and scripted approaches converge on the same request — the difference starts to matter
more in the later labs in this series, where extracting data character-by-character makes
scripting the meaningful advantage.

## What This Teaches Us

The vulnerability isn't really about the `category` parameter — it's about trusting *any* input to
sit safely inside a string literal in a query that has logic riding on what comes after it. The
`released` flag was meant to be an access control, but because it lived in the same query as
user-controlled input, closing the string early made it disappear entirely. Parameterized queries
close this off completely: with the category value bound as a literal parameter rather than
concatenated into the query text, an apostrophe in the input is just an apostrophe, and the
`released = 1` condition can never be commented out by a request.
