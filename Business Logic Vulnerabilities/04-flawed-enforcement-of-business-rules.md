# Flawed enforcement of business rules

**Category:** Business Logic Vulnerabilities
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-flawed-enforcement-of-business-rules

Discount logic is one of the oldest attack surfaces in e-commerce because "don't apply the same
coupon twice" sounds like a complete rule right up until you actually implement it. The easy version
of that rule only checks the single most recent coupon applied — which means it isn't really
checking for duplicate use at all, just for immediate repetition.

## The Target

The storefront offers two coupon codes: `NEWCUST5`, visible on the homepage, and `SIGNUP30`, granted
after signing up for the store's newsletter. Applying either code to the cart via
`POST /cart/coupon` reduces the total. The lab objective is again buying the leather jacket for less
than the account's store credit.

## The Investigation

Applying `NEWCUST5` once worked as expected. Applying it a second time in a row was rejected with an
"already applied" style response — a dedup check clearly exists. The question is what exactly that
check is keyed on. If it only compares the incoming coupon code against the *last* code applied to
the cart, then it never actually tracks a history of all codes used — it just refuses to apply the
same one twice consecutively.

We tested that hypothesis directly: apply `NEWCUST5`, then apply `SIGNUP30`, then apply `NEWCUST5`
again. If the check were a real "have I seen this code before" history, the third request would be
rejected identically to applying the same code back-to-back. It wasn't. Alternating between the two
codes bypassed the check every time, and each successful application reduced the cart total further.

## The Exploit

With the jacket in the cart, we alternated the two coupon codes:

```
POST /cart/coupon  coupon=NEWCUST5
POST /cart/coupon  coupon=SIGNUP30
POST /cart/coupon  coupon=NEWCUST5
POST /cart/coupon  coupon=SIGNUP30
...
```

Our verified record has this converging around 50 alternating applications to bring the $1337
jacket's total down below the account's $100 store credit. Once the total fell into that range, we
completed checkout normally and the order went through.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution finds the same two codes (`NEWCUST5` on the homepage, `SIGNUP30` from the
newsletter signup), applies both to the cart, notices that entering the same code twice in a row is
rejected while alternating between them is not, and reuses the two codes "enough times" to bring the
total under the remaining store credit before checking out.

This is the same technique end to end — the coupon-alternation bypass is the entire vulnerability,
and there's no alternate path around it. The only difference worth naming is that PortSwigger's
walkthrough leaves the exact repetition count to manual trial in Burp Repeater, while our script
looped the alternation automatically and read the cart total back after each request to know exactly
when to stop.

## What This Teaches Us

The dedup logic here checked the wrong thing: "is this the same code as last time" instead of "has
this code been applied before, ever, in this cart's lifetime." Any rule meant to prevent repeated use
of a limited resource — a coupon, a referral bonus, a free trial — needs to track a durable history of
what's already been consumed, not just compare against the single most recent state transition. A
sequence of individually-valid-looking actions can still violate the intended business rule when
looked at as a whole.
