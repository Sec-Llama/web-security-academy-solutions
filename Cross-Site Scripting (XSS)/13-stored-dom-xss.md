# Stored DOM XSS

**Category:** Cross-Site Scripting (XSS)
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-stored

This lab combines stored persistence with a client-side sanitizer that almost works — the comment
system runs submitted text through a sanitization routine before rendering it, but the sanitizer has
a specific, exploitable blind spot in how it handles repeated characters. That's a more realistic
bug shape than "no filtering at all": most production XSS vulnerabilities survive *some* defense,
just not a complete one.

## The Target

The blog's comment functionality, same as the earlier stored-XSS labs, but this time comments are
rendered client-side through JavaScript that calls `.replace()` on the submitted text to strip angle
brackets before writing it into the DOM via `outerHTML` (or an equivalent raw-HTML assignment).

## The Investigation

We tested how the sanitizer handled a comment containing multiple angle-bracket pairs. It became
clear the sanitization was implemented with a `.replace()` call that only touches the *first*
occurrence of the character it's targeting, rather than replacing every instance — a classic
`String.replace()` pitfall when the call isn't using a global flag. That means a payload with an
extra, sacrificial set of angle brackets in front of the real payload will have that first pair
stripped by the sanitizer, while the real payload right behind it survives untouched, because the
sanitizer's single pass is already spent by the time it reaches the second pair.

## The Exploit

We posted a comment with an extra `<>` pair immediately before the real event-handler payload:

```
<><img src=1 onerror=alert(1)>
```

The sanitizer's single-pass `.replace()` consumed the leading `<>`, leaving
`<img src=1 onerror=alert(1)>` completely intact in the sanitized output. That surviving tag then
got written into the DOM via the raw-HTML sink, and the broken `src=1` triggered `onerror`
immediately on render — persistently, for every subsequent visitor to the post.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's published solution for this lab is the same single-step payload, posted as a comment:
`<><img src=1 onerror=alert(1)>`. Their explanation of *why* it works matches the mechanism we
identified — the site's `replace()` call only strips the first occurrence of angle brackets, so a
throwaway pair absorbs the sanitization and the real payload passes through. Full agreement on both
payload and root cause; no divergence to reconcile. As with the other stored-XSS labs in this series,
the only real difference is that we posted the comment via a direct HTTP request (handling CSRF token
retrieval ourselves) rather than through the comment form in a browser, then used a headless browser
purely to confirm the stored payload executed on reload.

## What This Teaches Us

A sanitizer that only replaces the first match of a dangerous character is worse than no sanitizer at
all in one specific sense: it creates false confidence. The application "looks" defended — a quick
manual test with a single `<script>` tag would indeed get stripped — while a payload engineered
around the sanitizer's exact implementation detail sails through untouched. This is a good argument
for why sanitization logic needs to be tested adversarially, not just with the most obvious payload,
and why global replacement (or better, a well-audited sanitization library rather than a hand-rolled
`.replace()` call) matters as much as the decision to sanitize at all. The deeper fix, as always with
`outerHTML`/`innerHTML` sinks, is to avoid writing user-controlled data into raw-HTML sinks in the
first place — a correctly implemented allow-list-based sanitizer or a safe templating approach closes
off this entire bug class regardless of how many angle-bracket pairs an attacker stacks up front.
