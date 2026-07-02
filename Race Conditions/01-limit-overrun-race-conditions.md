# Limit overrun race conditions

**Category:** Race Conditions
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/race-conditions/lab-race-conditions-limit-overrun

Every "single-use" check in a web application — a coupon code, a gift card balance, a vote —
relies on the same unstated assumption: that the request which checks the resource and the
request which consumes it happen as one atomic operation. They usually don't. There's a gap
between "is this coupon still valid?" and "mark this coupon as used," and if that gap is wide
enough, sending enough requests through it at once means the check passes for all of them before
any of them get to update the database. This lab is the cleanest possible demonstration of that
gap, applied to a discount code instead of the more consequential things it also breaks.

## The Target

The lab is a store selling a Lightweight "l33t" Leather Jacket priced well above what our test
account (`wiener:peter`) has in store credit. The purchasing flow accepts a single-use discount
coupon, `PROMO20`, applied via:

```
POST /cart/coupon
csrf=TOKEN&coupon=PROMO20
```

Apply it once and the cart total drops by 20%. Try to apply it a second time and the application
correctly refuses with a "coupon already applied" style response — on the surface, the single-use
restriction looks solid.

## The Investigation

The interesting question isn't whether the coupon is single-use — it clearly is, sequentially.
The question is what "single-use" actually means on the server: is it enforced as one atomic
database operation, or as a check followed later by a write? Applying a coupon almost certainly
happens in at least two steps — read whether it's been used, then write that it has — and between
those two steps the server has no way to tell the difference between "this coupon hasn't been used
yet" and "this coupon hasn't been used yet, because nineteen other requests are asking the same
question at the same microsecond."

That's exactly the shape of bug our race condition tooling targets first: identify a limit-checked,
single-use endpoint, then flood it with identical requests inside as tight a time window as
possible, so every copy reads "unused" before any of them writes "used." We built this on our HTTP/2
single-packet engine — a raw `h2` connection that constructs every request's HEADERS/DATA frames
first and only calls `sock.sendall()` once all of them are queued, so every request leaves the
client in the same TCP write instead of trickling out one connection at a time. That removes
network jitter as a variable entirely; the only thing left standing between the coupon requests and
the race window is how the server itself schedules concurrent work.

## The Exploit

After logging in as `wiener`, adding the leather jacket to the cart, and pulling a fresh CSRF token
from the cart page, we fired 100 identical `POST /cart/coupon` requests carrying
`csrf=TOKEN&coupon=PROMO20` inside a single HTTP/2 packet. Out of that burst, 12-20 requests
consistently came back as successful applications rather than "already applied" — proof that the
same coupon was independently validated as unused by more than one concurrent request before any
of them committed their write.

Because each successful application stacks multiplicatively, 20 accepted coupons brought the
jacket's price down to `$1337 × 0.8^20 ≈ $15.40` — comfortably inside the account's credit, versus
`$1337 × 0.8^15 ≈ $47.31` at the lower end of what a given burst returned. Since the coupon gets
marked used after the first burst completes regardless of how many requests slipped through, our
approach re-logged-in and re-added the jacket for each attempt rather than trying to reuse a
session, retrying up to ten times until a burst landed enough successful applications to make the
final price affordable. The one operational snag worth naming: checkout (`POST /cart/checkout`)
returns a `303` redirect to `/cart/order-confirmation`, and that redirect had to be followed
manually rather than through an auto-redirecting HTTP client, since automatic redirect handling in
our client library was silently dropping the session cookie on the hop.

With the discounted total inside budget, checkout completed and the lab's solve condition — owning
the leather jacket — was met.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's own solution walks through the same three-phase structure our methodology is built
on: predict the collision (the coupon endpoint has an invisible "already applied" check that must
live somewhere between request and database write), benchmark the behavior (send duplicate coupon
requests in sequence, confirm the expected single-use rejection), then send the same requests in
parallel and watch multiple of them succeed. They document two separate paths depending on Burp
Suite edition: Professional users get a purpose-built "Trigger race condition" custom action that
automates the whole parallel-send workflow, while Community Edition users duplicate a Repeater tab,
group the copies, and use "Send group in parallel" manually.

The underlying vulnerability and exploitation logic are identical to ours — parallel requests
racing the same check-then-write gap. The difference is entirely in tooling: PortSwigger's path
runs through Burp Repeater's GUI (in either its automated or manual form), while ours runs through
a scripted HTTP/2 single-packet client built directly against the raw `h2` protocol library. Both
converge on the same mechanism — get every copy of the request onto the wire before the first one's
write lands — just from opposite ends of "point-and-click" versus "control the TCP write yourself."

## What This Teaches Us

The coupon's single-use restriction failed not because the check was wrong, but because the check
and the consequence of that check were separated in time, and the server let unrelated requests
interleave inside that separation. That's the entire race condition vulnerability class in
miniature: an operation that looks atomic from a single request's point of view isn't necessarily
atomic from the database's point of view. The fix is to collapse the check and the write into one
atomic operation — a single transaction, or a datastore-level constraint like a unique index on
"coupon applied to this cart" — so that no matter how many requests arrive at the same instant,
only one of them can ever observe the coupon as unused.
