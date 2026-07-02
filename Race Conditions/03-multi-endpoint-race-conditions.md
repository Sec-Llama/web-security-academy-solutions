# Multi-endpoint race conditions

**Category:** Race Conditions
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/race-conditions/lab-race-conditions-multi-endpoint

Every race condition so far in this series has been about racing an endpoint against itself —
duplicate copies of the same request fighting over the same check. Real multi-step business
processes open a different kind of window: one endpoint validates state, a second endpoint acts on
that state, and the two are only supposed to run in that order. Nothing enforces that they can't run
at the same time instead, on two entirely different code paths that both happen to read and write
the same underlying cart.

## The Target

The same storefront and the same overpriced Lightweight "l33t" Leather Jacket as the previous lab,
but this time our test account (`wiener:peter`) has only $100 of store credit against a $1337 item
— no discount coupon available to close that gap. The purchasing flow instead has two separate
moving parts: `POST /cart/checkout`, which validates that the cart's total doesn't exceed available
credit, and `POST /cart`, which adds items to that same cart. Both operate against the same
server-side, session-keyed cart state.

## The Investigation

If checkout validates the cart total once, at the start of processing the order, and only
*afterward* actually confirms the order using whatever the cart contains at that later point, then
there's a window between "total is checked" and "order is confirmed" during which the cart's
contents could change without triggering a second validation. That's a different collision shape
than the previous labs: not the same endpoint racing itself, but two different endpoints racing each
other, where the exploit is timing a cart-modification request to land inside the validation gap of
a checkout request that's already in flight.

The setup that makes this affordable: buy a $10 gift card first (`productId=2`), which brings the
cart's validated total safely under the $100 credit limit, then race a checkout of that $10 cart
against an `add jacket` request timed to land after validation but before order confirmation. If the
race lands correctly, checkout validates a $10 cart, and the jacket — added mid-flight — rides along
into the confirmed order for free.

We built this as two concurrent coroutines under an `httpx.AsyncClient(http2=True)`:
`do_checkout()` posting to `/cart/checkout`, and `do_add_jacket()` posting `productId=1&redir=
PRODUCT&quantity=1` to `/cart`, launched together via `asyncio.gather()`. Before firing the actual
race, we sent a plain `GET /` first to pre-establish the HTTP/2 connection to the backend — a
"connection warming" step that matters here specifically because a fresh TLS/HTTP2 handshake on the
first real request would introduce its own timing delay relative to the second request, undermining
the alignment we're trying to create between the two racing endpoints.

## The Exploit

With the gift card in the cart and the connection warmed, we fired `do_checkout()` and
`do_add_jacket()` simultaneously. Checkout on this lab returns `200` on success rather than the
`303` redirect from the single-endpoint coupon lab, so a successful race showed up as a `200`
checkout response followed by an order that included both the gift card and the jacket. The attack
was probabilistic — only around one attempt in nine actually landed the jacket inside the validation
window — and every failed attempt still cost $10 for the gift card purchase that had to be redone
before the next try, which put a real budget constraint on the attempt count: roughly ten tries
available from the $100 starting credit before running out of money to even attempt the race again.

Because the cart is stored server-side and keyed to the session rather than held client-side, both
endpoints — checkout and add-to-cart — were reading and writing the exact same underlying state,
which is what made racing two different URLs against each other meaningful in the first place. On a
successful attempt, the confirmed order contained the jacket despite it never being part of the cart
that checkout actually validated, closing out the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the same three-phase shape as the other labs in this series, scaled
up for a two-endpoint race: predict the collision across several numbered reconnaissance steps
(login, buy the gift card, identify the cart and checkout endpoints, reason about the session-keyed
cart), benchmark the timing with Repeater tab groups sent both sequentially and in parallel —
including their own connection-warming step, sending a plain homepage request first — and finally
prove the concept by removing the jacket, buying a fresh gift card, and sending the checkout and
add-to-cart requests in parallel via Repeater's "send group in parallel" feature.

The technique is identical to ours at every level that matters: same two-endpoint race, same
gift-card-to-afford-validation setup, same connection-warming trick to align timing, same underlying
insight that server-side cart state makes racing across endpoints work. The only real difference is
delivery — PortSwigger drives it through Burp Repeater's tab-group parallel-send feature, we drove
it through two `asyncio` coroutines dispatched together via `asyncio.gather()` over an HTTP/2
client. Notably, PortSwigger's own solution explicitly favors Repeater's parallel send over Turbo
Intruder for this particular lab, which lines up with our experience too: multi-endpoint races don't
need a single-packet burst of many identical requests the way limit-overrun attacks do, they need
exactly two requests launched together, which any concurrent HTTP client can do without specialized
tooling.

## What This Teaches Us

The vulnerability here isn't in either endpoint individually — checkout's validation logic is
correct, and add-to-cart's logic is correct — it's in the assumption that a user can't reach the
second endpoint while the first is still mid-flight. Multi-step business processes that validate
state at step one and act on state at step three are only as safe as the guarantee that nothing else
can touch that state in between, and HTTP doesn't provide that guarantee for free. The fix is the
same principle as every other lab in this series even though the attack surface looks different:
either lock the cart for the duration of the checkout transaction, or re-validate the cart's actual
contents atomically at the moment the order is confirmed rather than trusting an earlier check.
