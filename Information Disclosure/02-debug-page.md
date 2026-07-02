# Information disclosure on debug page

**Category:** Information Disclosure
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-on-debug-page

Debug endpoints are meant to be temporary — a diagnostic page a developer left reachable to check
environment variables during setup, never intended to survive into production. The problem is they
usually don't announce themselves in any navigation menu, so the only trace left behind is whatever
pointed to them in the first place. This lab is a clean example of that: the front door doesn't
show a debug page anywhere, but the page source does.

## The Target

A standard e-commerce homepage, functionally unremarkable from the outside. Nothing in the visible
UI links anywhere resembling a debug or diagnostics tool.

## The Investigation

Since the homepage itself gave no visible clues, the next place to look was the raw HTML — hidden
links are commonly left behind in developer comments rather than removed cleanly. We fetched the
homepage and extracted every HTML comment (`<!-- ... -->`), then searched each one for anything
that looked like a path. That surfaced a comment referencing a debug link pointing to:

```
/cgi-bin/phpinfo.php
```

`phpinfo.php` is about as classic a debug endpoint as they come — it's the standard PHP function
for dumping the entire runtime environment, and when it's reachable outside a controlled admin
context it discloses everything from loaded extensions to environment variables.

## The Exploit

We fetched the debug page directly:

```
GET /cgi-bin/phpinfo.php
```

The response was a full phpinfo dump. We searched it for a `SECRET_KEY` entry using a pattern built
to handle phpinfo's HTML table layout, where the key and value sit in adjacent `<td>` cells:

```
<td>SECRET_KEY</td><td>value</td>
```

That extraction pulled a `SECRET_KEY` value straight out of the environment table. We submitted it
as the answer:

```
POST /submitSolution
answer=<extracted SECRET_KEY value>
```

The lab tracker confirmed the solve.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the identical path: use Burp's "Find comments" engagement tool
against the site map to locate the HTML comment on the homepage referencing a link called "Debug"
that points to `/cgi-bin/phpinfo.php`, then send that request to Repeater and read the `SECRET_KEY`
out of the phpinfo output. There's no technique divergence here — the discovery mechanism (comment
scraping) and the extraction target (`SECRET_KEY` in the phpinfo table) are exactly the same on
both sides.

The only difference is, again, delivery. Burp's "Find comments" tool does the same regex-style
scan across the crawled site map that our script does across a single fetched page; we parsed the
comment and the phpinfo response with Python's `re` module instead of Burp's GUI-driven engagement
tools. For a single static comment on a single page, both approaches take about the same number of
steps — the automated version starts to pay off once "find every HTML comment across a whole site"
becomes the actual task.

## What This Teaches Us

The bug isn't that `phpinfo.php` exists — it's a legitimate diagnostic tool — it's that it was both
reachable without authentication and referenced from a comment on a public-facing page, which
turns "an internal debugging convenience" into "an information disclosure vulnerability anyone can
find." The fix is straightforward: debug endpoints don't belong in a production deployment at all,
and any pointer to them (in comments, JS bundles, or otherwise) needs to be scrubbed before code
ships, not left as a breadcrumb for whoever reads the page source.
