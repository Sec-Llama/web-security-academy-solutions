# Stored XSS into anchor href attribute with double quotes HTML-encoded

**Category:** Cross-Site Scripting (XSS)
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-href-attribute-double-quotes-html-encoded

This lab combines two things we'd only seen separately until now: a stored injection point (the
comment form's "website" field, rather than a one-shot reflected parameter) and an `href` attribute
sink where double quotes are actually encoded this time. That second detail matters — the earlier
`href` lab (DOM-based, jQuery `.attr()`) had no filtering at all on the destination string; this one
does, which forces a cleaner test of whether the `javascript:` scheme trick still works once quote
characters are off the table.

## The Target

The blog's comment form includes a "website" field intended to hold a URL, which the application
renders as the `href` of a link with the comment author's name as the link text. A normal comment
submission looks like a POST to `/post/comment` with `name`, `email`, `website`, and `comment`
fields plus a CSRF token.

## The Investigation

We stored a canary in the website field and reloaded the post page to see where it landed. It came
back inside the `href` attribute of the author's name link, as expected — but the double quotes we
also tested came back HTML-encoded (`&quot;`), meaning we couldn't close the attribute and inject a
new one the way we did in the previous lab's attribute context. That constraint didn't actually
matter here, though: the `href` attribute doesn't need arbitrary HTML injection to be dangerous —
it just needs to hold a scheme the browser will execute when the link is clicked, and nothing about
quote-encoding stops us from supplying a full `javascript:` URI as the *entire* attribute value.

## The Exploit

We stored the "website" field as a JavaScript URL, with no quotes needed at all:

```
javascript:alert(1)
```

```
POST /post/comment
postId=<id>&comment=click my name&name=attacker&email=a@b.com&website=javascript:alert(1)&csrf=<token>
```

Reloading the post page rendered `<a href="javascript:alert(1)" ...>attacker</a>`. Clicking the
author's name link executed the `javascript:` URI and fired the alert — for any visitor who clicked
it, since the payload persists in storage.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the same sequence: post a comment with a random string in the website
field, confirm via Repeater that it lands inside the anchor's `href`, then replace it with
`javascript:alert(1)` and click the author name to trigger it. Same injection point, same payload,
same technique — no divergence. The delivery difference is the pattern we've seen throughout this
series: their walkthrough intercepts and edits requests manually in Burp, we built and posted the
comment directly via HTTP client (handling CSRF token extraction ourselves) and used a headless
browser click-trigger to confirm the alert fired on the stored link.

## What This Teaches Us

Quote-encoding an attribute value defends against attribute-breakout attacks specifically — it does
nothing to defend against the attribute being fully attacker-controlled from end to end, which is
exactly what happens when a field like "website" is trusted to already be a safe URL. The real
vulnerability here isn't the missing quote-escaping at all; it's the absence of scheme validation on
a field that's rendered as a link destination. The fix is to explicitly allow-list acceptable URL
schemes (`http:`, `https:`, and reject everything else, including `javascript:`, `data:`, and
`vbscript:`) before persisting or rendering a user-supplied URL as an `href`, regardless of what
encoding is applied to the surrounding markup.
