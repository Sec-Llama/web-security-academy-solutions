# Single-endpoint race conditions

**Category:** Race Conditions
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/race-conditions/lab-race-conditions-single-endpoint

Not every race condition needs two endpoints or a repeated identical request to be dangerous.
Sometimes the same endpoint, hit with *different* values at the same time, is enough — if two
requests both touch a shared piece of server state and a background process later reads that state
back out, whichever request wrote last wins, regardless of which request the confirmation is
actually supposed to belong to.

## The Target

The application lets a logged-in user change their account email through
`POST /my-account/change-email`, which triggers a confirmation email to the new address containing
a confirmation link. Somewhere on this site, `carlos@ginandjuice.shop` has a pending administrator
invite that was never claimed — meaning whichever account successfully confirms that exact email
address inherits admin privileges. Our test account was `wiener:peter`, and the objective was to
claim `carlos@ginandjuice.shop` as our own confirmed email, then use the resulting admin access to
delete the `carlos` account.

## The Investigation

The obvious first hypothesis for "single-endpoint" race conditions is session variable collision:
two parallel requests to the same endpoint each set a session-scoped value, and the values get
mixed up between which request's session ends up with which value. That's not what's happening
here. The actual collision is at the database level and involves timing between two genuinely
separate operations that happen to both touch the same row: the change-email request updates a
`pending_email` column in the database, and a background email task later reads that same
`pending_email` column back out of the database — not from the original request's own parameters —
to decide what address to put in the confirmation email's body and link.

That distinction matters for the attack. If a second change-email request (for a different address)
overwrites `pending_email` after the first request's update but before the first request's email
task renders its template, the email that goes out under the *first* request's confirmation token
will contain whatever address the *second* request just wrote — a database race, not a session race,
surfaced through an asynchronous email-sending step that reads state back out after the fact instead
of carrying it forward in memory.

We sent twenty parallel `POST /my-account/change-email` requests carrying `csrf=TOKEN&email=EMAIL`
— ten requests for `carlos@ginandjuice.shop` and ten for distinct throwaway addresses on our
exploit server (`testN@exploit-server`) — reasoning that with enough interleaving, at least one of
the throwaway-address requests' email tasks would end up rendering with `carlos@ginandjuice.shop` in
the body instead of its own intended address, because the database had already been overwritten by
one of the carlos-targeted requests by the time that particular email task read it back.

## The Exploit

Checking the resulting inbox meant reading the *body* of each confirmation email, not just its
link — the whole point of the race is that a confirmation token generated for one email address can
arrive carrying `carlos@ginandjuice.shop`'s address printed in the message text, which is the
signal that this particular token's underlying database row was in the "carlos" state at render
time, whichever request the token itself belonged to.

Once an email turned up with `carlos@ginandjuice.shop` in the body, we HTML-unescaped its
confirmation link (the email client rendered `&amp;` where a raw URL would need `&`) and clicked
through. Not every token from the burst was usable — some had already been invalidated by later
requests in the same batch and returned `400` on confirmation — so this took retrying the burst
until a token came back both valid (`200`) and carrying the carlos body. A successful confirmation
changed our account's email to `carlos@ginandjuice.shop`, which flipped on admin access. From there,
`/admin` and a delete request for the `carlos` username closed out the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the same predict/benchmark/probe/prove structure as the rest of this
series, converging on the exact same underlying mechanism: the email-sending task reads the
account's pending email address back from the database at send time rather than carrying it forward
from the original request, so a parallel request that overwrites that column mid-flight can cause a
confirmation token generated for one request to arrive addressed to a completely different email.
Their proof-of-concept steps through duplicating Repeater tabs, modifying the email parameter across
copies, and sending the group both sequentially (to establish the expected one-token-per-request
baseline) and in parallel (to produce the collision) before manually inspecting which confirmation
email actually contains the target address.

The technique matches ours exactly — this is a genuine case where "single-endpoint" race conditions
turn out to be about backend state, not session variables, and both our reasoning and PortSwigger's
land on that same conclusion. The difference is scale and delivery: PortSwigger's walkthrough
demonstrates the collision with a small, manually inspected batch of Repeater requests, while we
scripted a twenty-request burst (ten toward the target address, ten toward throwaway addresses) and
automated the "check every returned email body, not just the ones we expect" step, since with more
concurrent requests in flight, checking bodies programmatically rather than by hand is what made a
larger, more reliable burst practical.

## What This Teaches Us

The bug here isn't in the change-email endpoint's validation — it's in a background process trusting
a database column to still hold the value it held at the moment the process was queued. Any
asynchronous step (email sending, notification dispatch, webhook delivery) that reads shared,
mutable state back out at execution time rather than carrying an immutable snapshot forward from the
triggering request is vulnerable to exactly this pattern: a parallel write to that same state,
timed to land in the gap between "task queued" and "task executes," can redirect the task's output
to an attacker-chosen value that was never part of the original request at all. The fix is to pass
the confirmed value into the background task explicitly at enqueue time, rather than having the task
re-read mutable state that a different request might change before it runs.
