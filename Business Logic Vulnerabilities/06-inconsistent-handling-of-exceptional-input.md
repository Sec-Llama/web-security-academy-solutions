# Inconsistent handling of exceptional input

**Category:** Business Logic Vulnerabilities
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-handling-of-exceptional-input

Truncation bugs are quietly dangerous because two different parts of the same system rarely agree on
where the cutoff is, or whether there's a cutoff at all. If a mail server will happily deliver to an
address of any length but the application database silently chops it down to fit a column, those two
components can end up with two different opinions about who owns a given account — and an attacker
who understands both limits can engineer an address that satisfies each system's expectations
independently.

## The Target

This is the same `@dontwannacry.com` employee-only admin panel from the "Inconsistent security
controls" lab, but this version doesn't allow simply changing your email post-registration — the
domain restriction is enforced at registration time and the email field isn't editable afterward.
The attack surface here is the registration form itself, and specifically how the server handles an
email address that's unusually long.

## The Investigation

Every lab in this series eventually asks the same underlying question: what happens at the edges of
an input the developer assumed would always be "normal length"? Email addresses are a natural
candidate — nothing in the RFC caps them anywhere near as short as a typical database `VARCHAR(255)`
column, and if the application truncates silently instead of rejecting an overlong address outright,
that truncation point becomes exploitable.

We confirmed the 255-character truncation experimentally, then worked out the exact construction
needed to abuse it. The idea: submit an email address longer than 255 characters where the *first*
255 characters, taken alone, form a string ending in `@dontwannacry.com` — even though the full,
untruncated address actually points somewhere else entirely (an inbox we control on the lab's
exploit-server domain). The mail server delivers the confirmation email to the full, real address;
the application's database — and therefore its access-control check — only ever sees the truncated
255-character prefix.

Building that string is arithmetic: `@dontwannacry.com` is 17 characters, so `255 - 17 = 238`
characters of padding are needed before it, followed by a `.` and the real domain to route the
message to our inbox:

```
"a" * 238 + "@dontwannacry.com." + email_client_domain
```

The trailing `.{email_client_domain}` after `@dontwannacry.com` makes the *full* address
technically deliverable to our exploit-server mailbox (since `@dontwannacry.com.{our-domain}` is a
subdomain of our domain from the mail system's point of view), while the first 255 characters read
as if the address genuinely ends at `@dontwannacry.com`.

## The Exploit

We registered with a unique username and the constructed 238-character-padded address, then
retrieved the confirmation link from the exploit-server's email client (search the page for the
`temp-registration-token` parameter) and visited it to complete registration. Logging in with the
new account and checking `/my-account` confirmed the stored email had indeed been truncated to
exactly the `@dontwannacry.com`-ending string. From there, `/admin` was accessible, and deleting
`carlos` solved the lab.

One practical detail worth recording: extracting the confirmation link from the email client's HTML
required care with the regex — an early version of the match caught a stray single quote from an
`href='...'` attribute, corrupting the URL and breaking the follow-up request.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution walks through discovering the truncation empirically first — register with an
exceptionally long but otherwise unremarkable address, confirm it, then check "My account" and
observe that the stored address has been cut to 255 characters — before constructing the actual
attack address: a long string followed by `dontwannacry.com` as a subdomain component, sized
precisely so that the "m" at the end of `@dontwannacry.com` lands exactly on character 255.

This is the identical technique and the identical truncation point — 255 characters, `dontwannacry.com`
positioned as a subdomain of the real receiving domain so the confirmation email still routes
correctly. The only difference is that PortSwigger's walkthrough demonstrates the truncation as a
separate, earlier step with a throwaway long address to prove the behavior exists before building the
real payload, while we went directly to the calculated 238-character construction, having already
confirmed the same 255-character limit was in play from the related "Inconsistent security controls"
lab in this series.

## What This Teaches Us

The vulnerability lives in the gap between two systems that both process the same field but disagree
about its valid range: an unbounded mail transport layer and a bounded application database column.
Neither behavior is wrong in isolation — truncating input to fit a column is common, and mail servers
routinely accept very long addresses — but treating the truncated value as authoritative for a
security decision, when a different, non-truncated interpretation of the same input was what actually
got verified by email, breaks the entire chain of trust the verification step was supposed to
provide. Any value used for both delivery and identity needs the two to be checked for equality
after the fact, not assumed to be the same string throughout.
