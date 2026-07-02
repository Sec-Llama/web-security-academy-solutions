# Lab: Unprotected admin functionality

**Category:** Access Control
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality

Broken access control has topped the OWASP Top 10 for years, and the simplest version of it is also
the easiest to miss: a page that does exactly what it's supposed to do for the people who find it,
and nothing to stop anyone else from finding it too. No auth check, no role check — just an
assumption that the URL is secret. This lab is that assumption, stripped down to its purest form.

## The Target

The application is a small blog site with a normal set of user-facing pages. Somewhere on the
server, unlinked from any navigation menu, sits an administrative panel with the power to delete
user accounts. Nothing in the visible site points to it directly.

## The Investigation

An admin panel that isn't linked anywhere still has to be reachable by *someone* — the developers,
at minimum, and probably automated tooling that needs to know which paths to leave alone. That's
exactly what `robots.txt` is for, and it's often the first place worth checking on a target like
this: a file whose entire purpose is to tell crawlers which paths exist but shouldn't be indexed.

We ran our admin-panel detector against the site, which checks `robots.txt` for `Disallow` entries
before falling back to brute-forcing a list of common admin paths (`/admin`, `/admin-panel`,
`/administrator`, `/management`, and similar):

```
[VERIFIED - Lab 1] Admin panel brute-force + robots.txt disclosure
/administrator-panel    -- VERIFIED (Lab 1: found via brute + robots.txt Disallow)
```

`robots.txt` disclosed a `Disallow` line pointing straight at `/administrator-panel`. The path
never needed guessing — the server told us about it directly, in a file meant to keep it out of
search results, not out of an attacker's browser.

## The Exploit

Loading `/administrator-panel` returned the admin interface with no login prompt and no session
check at all — just a working page listing every user account with a delete action next to each
one. Our script fetched the panel, located the delete link for `carlos` with a regex match against
the HTML, and followed it:

```
GET /administrator-panel
GET /administrator-panel/delete?username=carlos
```

The response confirmed `carlos` was gone, and the lab's solved banner appeared on the next request
to the homepage.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's published solution is the same discovery path: view `robots.txt`, notice the
`Disallow` line disclosing the admin panel path, load `/administrator-panel`, delete `carlos`.

This is a case where our approach matches the official one almost exactly, including the specific
discovery mechanism — we didn't need to fall back to brute-forcing, because `robots.txt` handed us
the path directly, just as the official solution describes. The only real difference is delivery:
PortSwigger's walkthrough is manual browser navigation, while our detector runs the `robots.txt`
check and a concurrent path brute-force together as one automated pass, so the same disclosure gets
caught whether or not a target happens to leave it in `robots.txt` specifically.

## What This Teaches Us

The vulnerability here isn't a flaw in any specific check — it's the total absence of one. The
application never asked "is this user allowed to be here" anywhere on the admin panel's code path,
and relied entirely on the URL being hard to guess. `robots.txt` broke that assumption for free,
but even without it, a predictable admin path was always one wordlist away from being found. The
fix isn't a better-hidden URL; it's an actual authorization check on every request to the panel,
enforced server-side, independent of whether the path is public knowledge.
