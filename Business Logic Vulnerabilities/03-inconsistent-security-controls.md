# Inconsistent security controls

**Category:** Business Logic Vulnerabilities
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-security-controls

Access control checks that only run once are barely access control checks at all. A surprising
number of real applications gate a privileged area behind a check performed at account creation —
"is this email address from an approved domain?" — and then never look at that value again for the
rest of the account's lifetime. If the field the check was performed on can still be changed
afterward, the check was only ever a speed bump.

## The Target

The storefront in this lab has an internal admin panel restricted to employees of a fictional
partner company, "DontWannaCry" — accessible only to accounts whose email address ends in
`@dontwannacry.com`. Registration is otherwise open to anyone, and the account's email address is
also editable later from `/my-account/change-email`.

## The Investigation

The natural first move is registering a normal account with any email address, confirming it
through the lab's own exploit-server email client, and logging in — this establishes what an
ordinary, non-privileged account looks like and confirms `/admin` returns an access-denied response
for it.

The real question is what "employee" actually means to the server at the moment `/admin` is
requested. If the access check re-reads the account's current email address from the database on
every request, changing that address later should immediately change the outcome. We tested exactly
that: after registering and confirming with an arbitrary address, we used the account's own
`/my-account/change-email` endpoint to set the email to an address on the `@dontwannacry.com`
domain — and nothing about that change required re-verifying the new address at all.

## The Exploit

The full sequence, run against a freshly registered and confirmed account:

```
POST /my-account/change-email
email=x@dontwannacry.com
```

No confirmation email loop, no re-verification token — the account's email field was simply updated.
Immediately afterward, `GET /admin` returned the admin panel instead of an access-denied page, and
from there deleting the user `carlos` solved the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution starts with Burp's content discovery tool to locate the `/admin` path (which
returns an error message hinting that DontWannaCry employees specifically have access), then
registers an account with an arbitrary email, confirms it via the lab's email client, logs in, and
uses the "My account" page's email-change option to set the address to an arbitrary
`@dontwannacry.com` value — landing on the same admin access.

This matches our approach exactly in substance. The one procedural difference is that PortSwigger's
walkthrough discovers `/admin` through Burp's automated content-discovery scan before trying it,
whereas we went straight to `/admin` directly — a reasonable shortcut once you already know this
family of labs consistently gates a hidden admin panel behind an email-domain check, but PortSwigger's
discovery step is the more general technique for a target where that path isn't already a known
convention.

## What This Teaches Us

The flaw isn't the domain check itself — restricting a panel to a specific email domain is a
reasonable-sounding control on paper. The flaw is where in the account's lifecycle that control gets
enforced: once, at registration, on a field the user can freely edit afterward with no re-verification
step. Any authorization decision based on a mutable piece of user data has to be re-evaluated at the
point of use, not cached from whatever was true the one time the value was checked.
