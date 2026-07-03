# Excessive trust in client-side controls

**Category:** Business Logic Vulnerabilities
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-excessive-trust-in-client-side-controls

Every business logic series has to start somewhere, and the most common root cause in the entire
category is this one: a server that assumes the client will only ever send back what it was given.
The browser renders a form, the form has a hidden field, and somewhere along the way a developer
decided that because the field isn't visible or editable in the UI, it doesn't need validating on
the way back in. That assumption is free money for an attacker who reads the request instead of the
page.

## The Target

The lab is the same e-commerce storefront that recurs throughout this series, and the objective is
concrete: buy a "Lightweight l33t leather jacket" that costs far more than the store credit on the
test account (`wiener:peter`). Adding an item to the cart sends a `POST /cart` request, and the
question worth asking before touching anything else is simple — what does that request actually
contain beyond the product ID and quantity a user would consciously choose?

## The Investigation

Reading the add-to-cart form's underlying request answers that question immediately: alongside
`productId` and `quantity`, the POST body carries a `price` field, populated server-side when the
page renders and submitted back unchanged by a normal browser. The price is expressed in cents (the
jacket lists at `133700`, i.e. $1337.00). Nothing in the checkout flow re-derives this value from
the product catalog when the order is placed — the server trusts whatever number arrives in that
field.

That's the entire vulnerability. There's no encoding trick, no timing element, no secondary
validation layer to route around. The price is just a form field, and form fields are attacker input
regardless of whether the UI presents them as editable.

## The Exploit

We added the jacket to the cart with the `price` field overridden:

```
POST /cart
price=1
```

instead of the legitimate `133700`. The server accepted the tampered value without complaint, the
cart total dropped to one cent, and checkout completed normally — well within the account's existing
store credit. The order confirmation page marked the lab solved.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's published solution reaches the same conclusion by a slightly different route: attempt
to buy the jacket first (it's rejected for insufficient credit), then study the `POST /cart` request
in Burp's HTTP history to notice the `price` parameter, send it to Repeater, and change the price to
"any amount less than your available store credit" before completing the order.

The technique is identical — override the client-supplied price — and the difference is exactly the
one this series keeps coming back to: PortSwigger's walkthrough finds and edits the parameter by hand
in Burp Repeater, we sent the tampered value directly through a scripted request. For a single
parameter override with no dependent state, both paths land on the same result in the same number of
requests.

## What This Teaches Us

The lesson here isn't really about price fields specifically — it's that "hidden" and "protected" are
not the same property. A field the UI doesn't let you edit is still a field the server has to
validate, because the HTTP request is the actual interface an attacker interacts with, not the
rendered form. The fix is to never let client-supplied data determine a monetary value at all: the
price should be looked up server-side from the product ID at checkout time, making the `price`
parameter in the request irrelevant even if an attacker sends whatever they like.
