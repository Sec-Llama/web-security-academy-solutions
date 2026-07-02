# Lab: Unprotected admin functionality with unpredictable URL

**Category:** Access Control
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality-with-unpredictable-url

Hiding a sensitive endpoint behind a random-looking URL feels like it should work — there's no
`robots.txt` entry to leak it and no wordlist likely to guess it. But "unpredictable" only holds if
the URL never appears anywhere the client can read it, and client-side JavaScript is client-side by
definition: anything the browser needs to reach that URL, an attacker's browser can read too.

## The Target

Same shape of application as the previous lab — a small blog site with an admin panel capable of
deleting users — except this time the panel's path isn't a guessable string like
`/administrator-panel`. It's something random. The only thing that's changed is how the site itself
reaches that panel.

## The Investigation

If `robots.txt` isn't going to give up the path this time, the next place worth checking is
whatever JavaScript the homepage ships to the browser. A site that needs to link to its own admin
panel from somewhere — even a hidden link, even a comment — has to embed that URL in something the
client parses, and unlike a server-side redirect, that's fully visible to us.

We fetched the homepage and ran a regex over the raw HTML/JS looking for anything path-shaped with
"admin" in it:

```
regex: ['"](/[a-zA-Z0-9_-]*admin[a-zA-Z0-9_/-]*)['"]  -- Extract from page source
```

That caught a JavaScript-embedded reference to the real admin panel path, sitting in the page
source the whole time — not linked in any visible menu, but present in the markup a browser
actually loads to render the page.

## The Exploit

With the path extracted from the page source, loading it directly returned the same kind of
unauthenticated admin interface as the previous lab. We located the delete link for `carlos` and
followed it:

```
GET /<unpredictable-admin-path>
GET /<unpredictable-admin-path>/delete?username=carlos
```

`carlos` was deleted, and the lab flipped to solved on the next homepage check.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the identical path: review the lab home page's source with
developer tools or Burp, notice the JavaScript disclosing the admin panel URL, load the panel,
delete `carlos`. The reasoning is the same reasoning we applied — a URL that has to be reachable by
legitimate client-side code can't stay secret from anyone reading that same code.

The only difference is mechanical: PortSwigger reads the page source by eye in the browser's dev
tools, while our script parsed the same HTML with a regex tuned to admin-shaped paths. Both land on
the same disclosed URL through the same underlying weakness.

## What This Teaches Us

"Unpredictable" is not the same as "secret." A URL becomes genuinely inaccessible to an attacker
only if the attacker's browser never has a legitimate reason to load it — and the moment a
front-end needs to link to an endpoint, that endpoint's address becomes part of the client-visible
attack surface, security through obscurity or not. The fix is identical to the previous lab: the
admin panel needs a real server-side authorization check. An unguessable path buys nothing against
an attacker who can read the same JavaScript the intended admin user's browser does.
