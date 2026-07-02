# Stored XSS into HTML context with nothing encoded

**Category:** Cross-Site Scripting (XSS)
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded

Stored XSS is the more dangerous sibling of reflected XSS for a simple reason: the payload doesn't
need a victim to click a crafted link, it just needs to sit in the database until someone else loads
the page. A blog comment field is the textbook place to find it, because comments exist specifically
to be stored and then displayed to every subsequent visitor. This lab puts that theory into practice
with the same lack of encoding as the reflected case, just moved into a persistence layer.

## The Target

The application is the same blog, this time with a comment form on individual post pages. Posting a
comment requires a name, an email, a website field, and the comment body, plus a CSRF token pulled
from the post page itself. Once submitted, the comment renders on that post's page for every visitor
who views it afterward.

## The Investigation

We treated the comment field the same way we treated the search parameter in the previous lab:
submit a value, then look at how it comes back — except this time "comes back" means loading the
post page again rather than reading the immediate response. We posted a comment and reloaded the
post. The comment text appeared in the page body exactly as submitted, with no HTML-encoding
applied to angle brackets or quotes. Same context as before — direct placement between tags — but
now every visitor to that post gets it, not just the person who made the request.

## The Exploit

We posted a comment using the standard script payload as the comment body:

```
POST /post/comment
postId=<id>&comment=<script>alert(1)</script>&name=attacker&email=a@b.com&website=&csrf=<token>
```

Reloading the post page executed the script and fired the alert — this time on any browser that
subsequently views that post, since the payload now lives in the comment store rather than in a
single request's response.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution matches ours exactly: enter `<script>alert(1)</script>` into the comment
box, fill in a name/email/website, submit, then go back to the blog to trigger it. The technique is
identical — nothing to reconcile. The only difference is mechanical: their walkthrough fills in the
form fields by hand through the browser, while we built and submitted the POST request directly with
an HTTP client (handling the CSRF token extraction ourselves) and then used a headless browser purely
to confirm the `alert()` fired on reload.

## What This Teaches Us

The vulnerability is identical to the reflected case in terms of root cause — unescaped output — but
the persistence changes the blast radius entirely. A reflected XSS payload only fires for whoever is
tricked into clicking a malicious link; a stored payload fires for every single visitor to the
affected page, with no social engineering required after the initial post. That's why stored XSS
against a public, unauthenticated comment section is treated as more severe than the equivalent
reflected bug: the attacker only has to deliver the payload once, and the application does the rest
of the distribution for them. The fix is the same as always — encode on output — but here it has to
apply consistently to anything ever read back from storage, not just to the current request's
parameters.
