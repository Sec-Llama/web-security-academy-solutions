# Source code disclosure via backup files

**Category:** Information Disclosure
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-via-backup-files

Source code was never meant to be public, which is exactly why editors and build tools leave
backup copies with predictable suffixes — `.bak`, `.old`, `~` — sitting right next to the files
they came from. If the web server serves static files from that directory without distinguishing
"this is source code with a backup extension" from "this is a downloadable asset," the entire
codebase becomes readable, hardcoded credentials included. This lab walks that exact path from a
crawler file to a database password.

## The Target

Another e-commerce storefront, this time with the interesting detail sitting in its `robots.txt` —
the file that's supposed to tell search engine crawlers what *not* to index, and which routinely
ends up pointing straight at the thing an operator most wanted hidden.

## The Investigation

We started with `robots.txt`, since `Disallow` entries are a direct list of paths someone decided
crawlers shouldn't touch — which makes it one of the highest-signal places to look first, precisely
because it was never meant to be a hint. Parsing the `Disallow:` lines out of the response turned
up a `/backup` entry. Browsing to that directory returned a listing rather than a 403, and the
listing contained a file link with a name that gave away exactly what it was:

```
ProductTemplate.java.bak
```

The `.bak` suffix on a `.java` file is as direct a signal as information disclosure gets — this is
almost certainly the original source file, still readable because the web server has no concept of
"serve `.java` but refuse `.java.bak`."

## The Exploit

We fetched the backup file directly:

```
GET /backup/ProductTemplate.java.bak
```

The response was the full Java source for a product template class, including its database
connection setup. The connection was built through a JDBC `ConnectionBuilder.from()` call, which
takes its arguments positionally — driver, database type, host, port, database name, username, and
finally password, in that order. The last positional argument was a hardcoded Postgres database
password sitting in plain text in the constructor call. We extracted it with a pattern built
specifically for that call signature and submitted it:

```
POST /submitSolution
answer=<extracted database password>
```

The lab tracker confirmed the solve.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the same chain start to finish: `robots.txt` reveals `/backup`,
`/backup` contains `ProductTemplate.java.bak`, and the source of that file contains the hardcoded
Postgres password inside the connection builder call. There's no divergence in technique at all —
this is one of the cases where the intended path and the one we took are the same request sequence.

The difference is, as usual, automation. Our script pulls every `Disallow` entry out of `robots.txt`
(not just `/backup` specifically), tries a set of backup extensions against files it finds linked in
any resulting directory listing, and runs several password-extraction patterns — including one
written specifically for the `ConnectionBuilder.from()` positional-argument shape — against
whatever it downloads. PortSwigger's walkthrough does the equivalent by hand: browse to
`robots.txt`, browse to `/backup`, open the file, read the password out of the visible source.

## What This Teaches Us

Two separate failures stack here. First, `robots.txt` telling crawlers to skip `/backup` is not
access control — it's a polite request that only well-behaved crawlers honor, and it actively
advertises the directory's existence to anyone who reads the file, which is exactly the audience it
shouldn't be advertising to. Second, and more seriously, hardcoded database credentials in source
code turn "a backup file got left on the web server" into "the production database is compromised."
The fix has to happen at both layers: backup and editor-swap files should never be deployed to a
web-accessible path in the first place, and credentials belong in environment variables or a secrets
manager, never typed directly into a constructor call — because source code has a way of ending up
somewhere it shouldn't, and a hardcoded secret in it means that mistake is no longer contained to
the code itself.
