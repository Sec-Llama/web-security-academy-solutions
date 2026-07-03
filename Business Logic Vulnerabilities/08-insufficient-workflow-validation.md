# Insufficient workflow validation

**Category:** Business Logic Vulnerabilities
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-insufficient-workflow-validation

A checkout flow is a sequence of steps for the same reason a state machine has states: each step is
supposed to be a precondition for the next. Add items, pay, confirm. If the confirmation step doesn't
actually check that payment happened — just that a request arrived at the confirmation URL — then the
sequence was never enforced server-side at all. It was a suggestion the UI made, not a rule the
backend upheld.

## The Target

The familiar storefront checkout: add items to the cart, `POST /cart/checkout` processes payment
against the account's store credit, and the server redirects to an order confirmation page. The
objective, as usual, is buying the leather jacket beyond what the account's store credit alone would
normally cover.

## The Investigation

Watching the checkout flow for a purchase the account *can* legitimately afford reveals its shape: a
successful `POST /cart/checkout` redirects to
`GET /cart/order-confirmation?order-confirmation=true`, which renders the "your order is complete"
page. The question this lab is built around is whether that confirmation GET request does any actual
work of its own, or whether it's purely a display step that assumes the checkout POST already did
everything necessary.

We tested that assumption directly: with the leather jacket sitting in the cart — priced well beyond
the account's store credit, meaning a legitimate `POST /cart/checkout` would be rejected outright —
we skipped the checkout POST entirely and requested the confirmation URL on its own.

## The Exploit

With the jacket in the cart, we sent the confirmation request directly, never having sent a
successful (or any) checkout request for it:

```
GET /cart/order-confirmation?order-confirmation=true
```

The server responded as though the order had been placed and paid for. No prior successful checkout
was required — the confirmation endpoint didn't verify that a matching payment had actually gone
through, only that the cart currently held items and the right query parameter was present. The lab
was marked solved with the jacket "purchased" for free, no payment step ever completed.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution maps out the flow the same way: buy something affordable first to observe
that `POST /cart/checkout` redirects to `GET /cart/order-confirmation?order-confirmation=true`, send
that GET to Repeater, then add the leather jacket to the basket and resend the confirmation request
directly — completing the order without the cost ever being deducted.

This is the same technique with no meaningful divergence: identify the workflow's final step, then
skip straight to it via forced browsing instead of following the sequence the UI implies. The
difference is, again, delivery — PortSwigger drives it through Burp Repeater after capturing the
request in proxy history, we replayed the same GET directly from a script once we'd read the flow
from our own testing.

## What This Teaches Us

Multi-step processes are only as secure as their weakest step's independence from the ones before
it. This confirmation endpoint was written to assume it could only ever be reached *after* a
successful checkout, because that's the only path the web UI offers — but an HTTP endpoint doesn't
enforce sequence just by existing at the end of a flow diagram. Every step in a workflow that has a
security-relevant side effect (marking an order paid, in this case) needs to independently verify
that the preconditions for that side effect actually hold, rather than trusting that a browser
following the intended sequence is the only way the request could ever arrive.
