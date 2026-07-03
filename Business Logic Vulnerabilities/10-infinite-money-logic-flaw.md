# Infinite money logic flaw

**Category:** Business Logic Vulnerabilities
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-infinite-money

Most of the logic flaws in this series are one-shot: find the flaw, trigger it once, get the payoff.
This lab is different — the flaw is a repeatable cycle with a small, positive net gain each time it
runs, which turns a minor discounting bug into effectively unlimited store credit if you're willing
to automate the loop. Small profit per iteration plus enough iterations is its own category of
business logic vulnerability, distinct from a single bypass.

## The Target

The storefront sells $10 gift cards, redeemable from the account page for $10 of store credit, and
separately offers the `SIGNUP30` coupon (unlocked by signing up for the newsletter) for 30% off. The
question is what happens when both apply to the same purchase: a $10 gift card discounted 30% costs
$7, and redeeming it still credits the full $10 — a $3 net gain, repeatable for as long as the coupon
and gift-card flow both keep working the same way.

## The Investigation

Confirming the $3-per-cycle gain was the easy part — buy a gift card with the coupon applied, redeem
the resulting code, and watch the store credit balance. The harder part was making that cycle reliable
enough to run several hundred times unattended, because a checkout flow built for a human clicking
through a browser has assumptions baked in that don't hold up under rapid automated repetition.

Several details turned out to matter for reliability, all discovered through the loop actually
failing partway through long runs:

- `POST /cart/checkout` needed `follow_redirects=False`. Following the redirect automatically
  collapsed the checkout POST and the confirmation GET into one HTTP round trip from the client's
  point of view, which wasn't reliable for making sure the gift card code existed by the time it was
  read. Treating them as two separate requests — checkout, then a standalone GET to the confirmation
  page — fixed that.
- The confirmation page at `GET /cart/order-confirmation?order-confirmed=true` (note: `confirmed`,
  not `confirmation` — a different query parameter from the workflow-validation lab's endpoint)
  accumulates *every* gift card code ever generated on the account, newest first. Extracting the
  correct code for the current cycle meant taking the first `<td>` entry after the "following gift
  cards:" marker in the response, not searching the whole page or trying to track which codes had
  already been used — with the list growing past 400 entries over a full run, any kind of
  already-used tracking became unreliable, while "always take the first one" stayed correct by
  construction.
- The CSRF token needed refreshing from `/my-account` every single cycle, not just once at the start
  — tokens expired over the length of a run this long.
- A `GET /my-account` between cycles, beyond just refreshing the CSRF token, also acted as a sync
  buffer — omitting it produced intermittent failures under rapid back-to-back requests.

## The Exploit

Each cycle became six requests:

```
POST /cart               productId=<gift card>, quantity=1
POST /cart/coupon         coupon=SIGNUP30
POST /cart/checkout       (follow_redirects=False)
GET  /cart/order-confirmation?order-confirmed=true
POST /gift-card           gift-card=<code extracted from the FIRST <td> after "following gift cards:">
GET  /my-account           (sync buffer + CSRF refresh for the next cycle)
```

Our internal record shows roughly 412 cycles were needed to grow the account's store credit from the
starting $100 up to the $1337 required for the jacket, at $3 net gain per cycle. After the loop
completed, buying the jacket and checking out normally solved the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution identifies the same $3-per-cycle mechanism (buy a discounted gift card,
redeem it, net gain), then automates it using a Burp session-handling rule built around a five-request
macro: `POST /cart`, `POST /cart/coupon`, `POST /cart/checkout`,
`GET /cart/order-confirmation?order-confirmed=true`, `POST /gift-card` — with the macro configured to
pull the gift-card code from the confirmation response and feed it automatically into the redemption
request's `gift-card` parameter. That macro is then driven by sending `GET /my-account` to Intruder
with null payloads, generating exactly 412 requests with concurrency capped at 1, to run the macro
412 times sequentially.

This is a very close match — same five core requests per cycle, and PortSwigger's own solution
lands on the identical 412-cycle count our script converged on independently, which is a strong
confirmation that both approaches are extracting the same $3/$1237 economics correctly. The
difference is our sixth request: PortSwigger's Burp macro handles token/state continuity through
Burp's session-handling rule engine, which re-runs the macro's own internal request chain
transparently; our script needed an explicit extra `GET /my-account` between cycles to refresh the
CSRF token and act as a pacing buffer, since we didn't have an equivalent macro engine managing that
continuity for us. Functionally the two approaches converge on the same operation repeated the same
number of times — automated request replay at volume, whether driven by Burp Intruder's null-payload
attack or a Python loop.

## What This Teaches Us

Individually, a 30%-off gift card and a full-value redemption are each defensible features. The flaw
only exists in their intersection: nothing in the business logic checked whether the *discounted*
price paid for a gift card matched the *full* value it could be redeemed for, and nothing rate-limited
or capped how many times that mismatch could be exploited in sequence. Small positive-EV loops like
this are easy to dismiss as "only $3" in isolation, but the entire point of automation is that $3
times a few hundred cycles is real money — any promotional mechanic that can be composed with a
redemption mechanic needs the combined economics checked, not just each piece in isolation.
