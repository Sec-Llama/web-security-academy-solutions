# Low-level logic flaw

**Category:** Business Logic Vulnerabilities
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-low-level

Integer overflow is usually filed under memory-safety bugs in C code, but it's just as real in a web
application's cart total if that total is stored as a fixed-width signed integer somewhere in the
stack. A 32-bit signed integer tops out at 2,147,483,647. Push a running total past that boundary and
it doesn't error — it wraps around to the most negative value the type can hold and starts counting
up from there. A shopping cart that can be pushed past that ceiling has effectively been given a
second, negative price list.

## The Target

Same jacket, same insufficient store credit, but this time the earlier tricks don't apply cleanly:
the add-to-cart quantity field only accepts a 2-digit value per request (max 99), which rules out
sending one enormous quantity in a single shot. The path to an overflow here has to be built out of
many requests.

## The Investigation

With a 99-unit cap per request, reaching the 32-bit boundary means repeated additions. The jacket
lists at $1337.00 (133700 cents), so each maxed-out request adds `99 * 133700` cents to the running
total. Enough of those requests in sequence will eventually push the signed 32-bit total past
2,147,483,647, at which point it wraps to a large negative number and starts climbing back toward
zero with every further addition.

The naive version of this attack — just keep adding 99 jackets until the total looks reasonable — is
slow and imprecise. We treated it as a modular arithmetic problem instead: the final total after
`n` batches of 99 jackets is `(n * 99 * jacket_cents) mod 2^32`, and the goal is finding an `n` (plus
an optional smaller offset quantity of a second, cheaper product) that lands this value inside
`(0, 10000]` cents — comfortably under the $100 store credit — while minimizing the total number of
HTTP requests needed to get there. Scanning batch counts in a plausible range (roughly 162 to 340
batches) and checking the modular result for each was fast to compute locally, well before sending a
single request.

One practical snag along the way: pulling reference prices from individual product pages
occasionally picked up the string "Store credit: $100.00" instead of a product price, because both
values matched the same loose regex. Reading prices from the shop's listing page instead, where only
clean product prices appear, avoided the contamination.

## The Exploit

Once the target batch count and offset quantity were computed, the execution was mechanical:

1. Send `POST /cart` with `productId=1` (the jacket) and `quantity=99`, repeated for the computed
   number of batches — reusing the same CSRF token across all of them, since the token stayed valid
   for the whole session.
2. Send the computed offset quantity of the cheapest other product in the shop, in further batches
   of up to 99, to fine-tune the total into the target window.
3. Read the cart total back and, if it wasn't yet inside `(0, 100]`, add one more unit of the offset
   product at a time until it was.
4. Checkout.

Roughly 324 batches of 99 jackets brought the running total from over $2.1 billion (in cents) down
past the wraparound point to around -$64,000, and the offset product's quantity closed the remaining
gap into the affordable range. The order completed and the lab was marked solved.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the same 32-bit wraparound, but via Burp Intruder rather than
computed batch math: send the `POST /cart` request to Intruder with `quantity=99`, run a null-payload
attack configured to "continue indefinitely," and watch the cart total in a browser tab until it
flips from a huge positive number to a large negative one. From there, the solution clears the cart,
runs a second Intruder attack generating *exactly* 323 payloads (with concurrency capped at 1 request
at a time, to keep the requests strictly sequential), sends one more manual request for 47 jackets to
land at -$1221.96, and finally adds a suitable quantity of a second item to bring the total into the
$0–$100 range before checking out.

The underlying vulnerability and mechanism are identical — the same 32-bit signed overflow, the same
99-per-request ceiling, even the same two-phase "overflow then fine-tune with a second product"
structure. The difference is *how* the precise request count gets found: PortSwigger's walkthrough
gets there empirically, watching the cart update live in Intruder and reading off 323 and 47 as the
numbers that work for this specific price point. We derived the same kind of numbers — 324 batches
plus an offset — by solving the modular arithmetic directly rather than watching a live total, which
also made it straightforward to pick whichever offset product minimized the number of HTTP requests
needed, not just whichever number happened to come up first by observation.

## What This Teaches Us

This is the same trust-boundary problem as the earlier client-side and quantity labs, just one layer
lower in the stack: server-side validation caught the case of a single malicious value (the 2-digit
quantity cap), but nothing validated the *accumulated* result of many individually-valid requests.
Fixed-width integer types have hard boundaries, and any value derived from repeated user-controlled
additions — cart totals, counters, balances — needs range-checking after every update, or checked
arithmetic that fails loudly on overflow instead of wrapping silently into a different, unintended
number.
