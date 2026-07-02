# Reflected XSS into HTML context with nothing encoded

**Category:** Cross-Site Scripting (XSS)
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded

Cross-site scripting is the vulnerability class that makes "don't trust the client" a rule instead
of a suggestion — every reflected XSS bug ultimately comes down to a server taking a user's own
input and echoing it back into a page as if it were trusted markup. This lab is the purest version
of that mistake: a search box whose value goes straight into the HTML with no encoding at all. It's
the natural starting point for a series on XSS because every other lab in this topic is a variation
on the same question — where does our input land, and what does the page do with it before we can
change that answer.

## The Target

The application is a blog with a search feature. A normal search request looks like:

```
GET /?search=test
```

and the response echoes the search term back into the page, presumably to show the user what they
searched for.

## The Investigation

The only real question for a reflected parameter is where in the response it lands and whether
anything encodes it on the way. We sent a search term and looked at the raw response: the value
came back verbatim, sitting between two HTML tags rather than inside an attribute or a script
block. No `<` or `>` had been converted to `&lt;`/`&gt;`, and no quotes had been touched. That's the
simplest possible context to work with — if the page will place our string directly into the body
of the HTML, we don't need to break out of anything. We can just supply a tag.

## The Exploit

We submitted the standard `<script>` payload directly as the search term:

```
GET /?search=<script>alert(1)</script>
```

The response contained the literal `<script>alert(1)</script>` tag inside the page body, and the
browser parsed and executed it on load, firing the alert.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's published solution is the same two steps: paste `<script>alert(1)</script>` into the
search box and click Search. There's no divergence in technique here — this lab has exactly one
intended path, and we took it. The only difference worth naming is delivery: their solution assumes
manual entry into the search box through the lab's own UI, while we drove the same request directly
with an HTTP client and confirmed execution with a headless browser listening for the `alert()`
dialog. For a single unauthenticated GET request, those two approaches are functionally identical.

## What This Teaches Us

Nothing about the `search` parameter suggested danger on its own — the risk was entirely in what the
server did with it after the fact: concatenating unescaped user input into an HTML response is
already a complete vulnerability, no filter bypass or context-breaking required. The fix is output
encoding: HTML-encode `<`, `>`, `&`, and quote characters before writing user input into the page,
so a browser sees `&lt;script&gt;` as literal text rather than a tag to parse. Every later lab in
this series exists because some encoding or filtering *was* in place — this one is the baseline for
what happens when there's none at all.
