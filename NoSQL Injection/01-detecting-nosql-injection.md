# Detecting NoSQL injection

**Category:** NoSQL Injection
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-detection

SQL injection gets most of the attention, but swapping the backend database doesn't remove the
underlying mistake — it just changes the syntax an attacker needs to abuse it. MongoDB and its
peers evaluate query fragments as JavaScript-like expressions rather than SQL, which means the
same core flaw (user input concatenated straight into a query with logic riding on it) shows up
wrapped in `'||1||'` instead of `' OR 1=1--`. This lab is the entry point for that family of bugs:
a category filter that leaks unreleased products the moment you stop treating its input as inert.

## The Target

The lab is a storefront where browsing a category sends a request like:

```
GET /filter?category=Accessories
```

The response lists the products in that category. As with the equivalent SQL injection labs, some
products exist in the database but are marked unreleased and are excluded from every normal
category page. That exclusion lives inside the same query that filters by category, which is
exactly the shape of bug worth testing for.

## The Investigation

Our general approach to a suspected MongoDB injection point, documented in our own NoSQL
methodology notes, is to work up through three checks before committing to an exploit: confirm a
character is being interpreted rather than escaped, confirm the application evaluates conditional
logic rather than treating the value as a flat string, then override whatever hidden condition is
riding alongside the input. For a `$where`-style JavaScript context, that means testing a false
condition and a true condition side by side:

```
' && 0 && 'x     -> false, should suppress all results
' && 1 && 'x     -> true, should behave like an unmodified query
```

If those two produce different result sets, the category value is being spliced directly into a
JavaScript expression the database evaluates per document — not compared as an opaque string. From
there, the same logic that works against a SQL `WHERE` clause works here: replace the condition
with something that's true regardless of what the application appends after it.

## The Exploit

We pulled a valid category name from the storefront's own homepage (`Accessories`, in our run) and
requested it with a tautology appended, closing the string and forcing the boolean check to always
succeed:

```
GET /filter?category=Accessories'||'1'=='1
```

Against a query shaped like `this.category == 'Accessories' && this.released == 1`, this turns the
second condition into `'1'=='1'`, which is unconditionally true, so every document matches
regardless of its `released` flag. We measured this directly by counting product images in the
response: the unmodified category page returned 7 images, and the injected request returned 33 —
26 additional products that only exist because the release filter had been neutralized.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's published solution reaches the same place through the same reasoning, worked
manually in Burp Repeater: submit a bare `'` to confirm the value isn't sanitized (it produces a
JavaScript syntax error), submit a syntactically valid payload like `Gifts'+'` to confirm the
input is being concatenated into an expression rather than rejected, then test a false condition
(`Gifts' && 0 && 'x`) against a true one (`Gifts' && 1 && 'x`) to confirm boolean control, and
finally submit an always-true override — `Gifts'||1||'` — to reveal the unreleased products.

The technique is identical to ours; the only real differences are cosmetic. PortSwigger's final
payload uses a bare truthy `1` (`'||1||'`), while ours uses an explicit string equality tautology
(`'||'1'=='1`) — both exploit the same short-circuit behavior in a JavaScript boolean expression,
they just spell "always true" two different ways. The other difference is delivery: PortSwigger
drives this through Burp's Proxy/Repeater workflow by hand, while we measured the effect
programmatically — pulling a live category name from the homepage and diffing image counts between
the baseline and injected requests instead of eyeballing the rendered page.

## What This Teaches Us

The `released` flag here is doing the same job as the SQL labs' hidden `WHERE` clause: it's an
access control that only works if the query's structure can't be altered by the value being
filtered on. Once the category parameter lands inside a JavaScript boolean expression evaluated
per document, an attacker doesn't need to know the field name or its value — they only need a
condition that's true no matter what. The fix is the same principle that applies everywhere in this
series regardless of the database engine: user input has to be treated as data, never spliced into
the logic of the query itself.
