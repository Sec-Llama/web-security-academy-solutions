# Lab: Using application functionality to exploit insecure deserialization

**Category:** Insecure Deserialization
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-using-application-functionality-to-exploit-insecure-deserialization

Not every deserialization bug needs a magic method or a gadget chain to become dangerous.
Sometimes the application's own legitimate functionality is the payload delivery mechanism: change
a value in a serialized object, and a completely ordinary feature — one that was never meant to be
security-sensitive — does the damage for you when it runs. This lab is about recognizing that a
"safe" feature can become an attack primitive the moment its inputs come from a tamperable object
instead of the user directly choosing them.

## The Target

Same session mechanism as the previous two labs: a base64-encoded, PHP-serialized `User` object as
the cookie. This account also has an avatar feature, and account deletion — `POST
/my-account/delete` — is exposed to any logged-in user for their own account. Deleting your account
is an intentional, unremarkable feature. The question this lab poses is what else that delete
operation touches beyond the account record itself.

## The Investigation

The serialized session object carries an attribute pointing at the user's avatar file on disk —
its name in the class definition. When we decoded the cookie, that file-path attribute was plainly
visible and, like every other field in the object, entirely attacker-editable before the request
went back to the server. The account-deletion feature, when it runs, doesn't just remove the
database row for the account — it also cleans up the avatar file at the path stored in the
session's own object. That's the whole vulnerability: a filesystem delete operation that trusts a
path coming out of client-controlled deserialized state, wrapped inside a feature (delete my own
account) that looks completely self-contained and harmless from the outside.

## The Exploit

We repointed that avatar-path attribute at the lab's target file, `/home/carlos/morale.txt`, updating
the serialized string's length prefix to match the new value's length (23 characters), base64-
encoded the modified object, and sent it as the session cookie on a `POST /my-account/delete`
request. Our own test script probes a small set of candidate attribute names for this field
(`avatar_link`, `image_location`, `avatar`, `profile_picture`) rather than hardcoding one, and our
internal notes don't isolate which single name fired the deletion in our own run — worth stating
plainly rather than asserting a specific attribute name we can't confirm from our own log. What we
can confirm is the mechanism and the trigger: modify the file-path field, submit the account-
deletion request, and the account-deletion code path deletes whatever path the object now claims
as the avatar file, which was no longer our own avatar at all.

We also authenticated with a secondary account (`gregg`) rather than the primary `wiener` account
for this particular lab run — since the exploit's own action is a self-account deletion, using a
backup account preserved the primary account for retries if the first attempt at the file path
didn't land.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's official solution targets this same attribute by name: `avatar_link`, changed from
its original value to `/home/carlos/morale.txt` with the length prefix updated to `23`, giving
`s:11:"avatar_link";s:23:"/home/carlos/morale.txt"`. The trigger step is identical to ours —
submit the modified cookie on `POST /my-account/delete`, which deletes the account and, as a side
effect of that deletion routine, the file now referenced by `avatar_link`.

Our script's first candidate attribute name was exactly `avatar_link`, matching PortSwigger's
target — so the technique lines up precisely; the one honest gap in our own record is that we
didn't log which of the candidate names our script actually matched on this run, since the code
was written to try several generically rather than assume the name in advance. The delivery
difference is the same one seen in the previous labs: Burp Inspector edits the cookie by hand, our
script edits and re-encodes it programmatically.

## What This Teaches Us

This lab is a reminder that deserialization vulnerabilities don't require a dangerous magic method
to be dangerous — an entirely mundane, intentional feature can become the exploit primitive if any
of its inputs trace back to attacker-controlled deserialized state. "Delete my own account" is a
safe operation in isolation; it stops being safe the instant the file path it cleans up is sourced
from a client-editable object rather than looked up server-side from the account record. The fix
here isn't specific to deserialization at all — it's the same lesson as any path-traversal or
IDOR-adjacent bug: never let a client-supplied value determine which file on disk a privileged
operation touches. Deserialization just made that client-supplied value easy to miss, because it
arrived wrapped in the format of the session cookie rather than as an obvious request parameter.
