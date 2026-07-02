# Partial construction race conditions

**Category:** Race Conditions
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/race-conditions/lab-race-conditions-partial-construction

The race conditions in this series so far have all exploited a gap between checking a resource and
updating it. This lab exploits a gap that opens even earlier: the moment between when a database row
starts to exist and when it finishes being fully initialized. An object under construction is a
strange kind of vulnerable — not missing, not present in its final form, just present enough that a
loosely-typed comparison can be tricked into treating "not yet set" as "matches whatever I sent."

## The Target

Registration on this site requires an `@ginandjuice.shop` email address and a follow-up email
confirmation step before the account is usable. The objective was to register an account using an
email address we don't actually control, bypass the confirmation requirement entirely, and use the
resulting account to delete the `carlos` user from the admin panel.

## The Investigation

Digging into the client-side JavaScript (`/resources/static/users.js`) surfaced the confirmation
endpoint's actual shape: a `POST /confirm` carrying a `token` query parameter. Probing that endpoint
by hand with a Repeater-style request revealed three distinct behaviors depending on what the
`token` parameter looked like: a syntactically plausible but wrong token returned an "Incorrect
token" message, an outright missing parameter returned "Missing parameter: token," and an empty
token value returned "Forbidden." None of those three responses is a bypass on its own — but the
distinct wording for each case meant the endpoint was doing real type/presence checking on the
token, which raised the question of what happens with a value that's present, but not a plain
string at all.

PHP has a well-known quirk here: submitting a parameter as `token[]=` rather than `token=` gets
parsed server-side as an empty array rather than an empty string or a missing key. Sending
`POST /confirm?token[]=` came back with a different message again — "Invalid token: Array" — rather
than the "Forbidden" that an empty string produced. That's a meaningfully different code path: the
server accepted the array-typed value as *a* token, just not the *correct* one, which meant whatever
comparison was checking the submitted token against the stored one was doing so with PHP's loose
(`==`) semantics rather than a strict, type-aware comparison. Loose comparison in PHP treats an empty
array as equal to `null` — which is exactly what a user row's confirmation-token column would hold
during the brief window between the row being `INSERT`ed (user created, token column not yet set)
and a follow-up `UPDATE` assigning the real token. If a confirmation request carrying `token[]=`
lands inside that window, `[] == NULL` evaluates true, and an account gets confirmed without ever
possessing a real token at all.

Timing that window meant understanding how long it actually stays open. Sending registration and
confirmation requests side by side, sequentially and then in small parallel bursts, showed
confirmation responses consistently returning much faster than registration responses — the
registration request itself does more work (creating the row, presumably queuing the confirmation
email) than a confirmation lookup does, which meant a naive "send both at once" approach would let
confirmation race ahead and miss the window entirely, arriving before the row even existed rather
than after it existed but before its token was set.

## The Exploit

We built this as a single HTTP/2 packet containing one registration request and twenty confirmation
requests together, on the theory that firing confirmation attempts as an entire spread across the
same TCP write — rather than trying to precisely delay a single confirmation request relative to one
registration request — would put enough confirmation attempts in flight that some of them would land
inside the brief NULL-token window regardless of the registration/confirmation processing-time
mismatch we'd observed.

Each attempt used a freshly generated random username (`racerXXXXXX`, six random lowercase letters)
to avoid collisions with rows left behind by earlier failed attempts, with a matching
`racerXXXXXX@ginandjuice.shop` email and a fixed password. Before every burst, we fetched a new CSRF
token and `phpsessionid` from a fresh `GET /register`, since both are required on the registration
request and tied to that specific session. The burst itself was:

```
POST /register
csrf=TOKEN&username=racerXXXXXX&email=racerXXXXXX@ginandjuice.shop&password=password123

POST /confirm?token[]=      (x20, empty body, no session cookie required)
```

— all built as HTTP/2 HEADERS/DATA frames and flushed in a single `sock.sendall()`, exactly the same
single-packet mechanism used for the limit-overrun lab earlier in this series. Twenty confirmation
requests per burst turned out to be close to an optimum: fewer consistently missed the window
entirely, and pushing meaningfully past twenty risked growing the packet past what still reliably
went out as a single TCP write.

The race is inherently probabilistic — roughly one attempt in twenty-five actually caught the window
— so this ran as a retry loop, generating a fresh username each time and re-fetching CSRF/session
before every burst. It won on the 23rd attempt, with the 11th of that attempt's twenty confirmation
requests landing inside the NULL-token window and confirming an account we'd never actually verified
ownership of. From there, logging in as that `racerXXXXXX` account, opening `/admin`, and posting a
delete request for `carlos` (with a fresh CSRF token from the admin page) closed out the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution arrives at the identical root cause through the identical reconnaissance
path: find the confirmation endpoint in the client-side JavaScript, probe the `token` parameter's
type handling, and discover that `token[]=` produces an "Invalid token: Array" response distinct
from a missing or empty token — the same tell that PHP's loose comparison is treating the submitted
array as potentially matching a NULL stored value. Their proof of concept uses Turbo Intruder's
`race-single-packet-attack.py` template directly from Burp: select the username parameter, send it
to Turbo Intruder, set an unused email address, and modify the template to queue one registration
request alongside fifty-plus confirmation requests behind a shared gate, then open the gate to fire
them together — reading results back by sorting the Length column for a `200` response containing an
"Account registration for user" success message.

The underlying vulnerability, the PHP empty-array trick, and the single-packet delivery mechanism
are all identical between their solution and ours — this lab is fundamentally about recognizing the
loose-comparison bug and then brute-forcing the timing window with volume, and both approaches do
exactly that. The concrete difference is tooling and scale: Turbo Intruder is a purpose-built Burp
extension that handles the single-packet HTTP/2 construction internally and queues fifty-plus
confirmation requests per burst; we built the equivalent single-packet HTTP/2 client ourselves
directly against the `h2` library, with `conn.data_to_send()` batching every queued frame so that one
`sock.sendall()` call is the single packet, and settled on twenty confirmation requests per burst
rather than fifty or more after finding that count balanced hit-rate against staying inside a single
TCP write. That we could reach the same result without Turbo Intruder at all — using nothing but
Python's `h2` and `socket` libraries — is itself worth noting: this lab is rated Expert on the
strength of the reconnaissance needed to find the loose-comparison bug and the precision needed to
exploit the timing window, not because the single-packet technique specifically requires Burp
tooling to pull off.

## What This Teaches Us

This is the most subtle race window in the series because the vulnerable state isn't a value that's
wrong, it's a value that doesn't exist yet — and a loosely-typed language treating "doesn't exist"
as equivalent to a specific attacker-controlled input turned an ordinary two-step object construction
into an authentication bypass. Multi-step creation processes (insert a row, then populate its
security-relevant fields in a follow-up step) inherently create this exact window, and the fix has
two independent layers: close the race itself by making user creation and token assignment a single
atomic operation rather than sequential steps, and — just as important — never let application logic
compare user-controlled input against a security-critical database field using loose or type-coercing
equality, since even a properly closed race window doesn't help if `null == []` is still true
somewhere else in the codebase.
