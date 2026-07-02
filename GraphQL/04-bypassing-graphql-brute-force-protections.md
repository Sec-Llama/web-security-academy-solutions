# Lab: Bypassing GraphQL brute force protections

**Category:** GraphQL API vulnerabilities
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/graphql/lab-graphql-brute-force-protection-bypass

Rate limiters are usually built around a simple unit of measurement: one HTTP request, one attempt. That assumption holds fine for a REST login endpoint, where a request and an operation are the same thing. GraphQL breaks the assumption outright — a single HTTP request can carry dozens of independent operations, each with its own arguments and its own result, and a rate limiter counting requests instead of operations will wave the whole batch through as if it were one login attempt.

## The Target

Login on this lab is a GraphQL mutation rather than a form submission, sent to `/graphql/v1` over `POST`/`application/json`. Behind it sits a rate limiter that starts returning errors once it sees too many requests from the same origin in a short window — the kind of defense that looks solid against a conventional brute-force tool sending one credential pair per HTTP request.

## The Investigation

We confirmed the rate limiter the straightforward way: a handful of repeated `login` mutation attempts against the endpoint, each carrying a different password, started coming back with rate-limit errors after only a few requests. That ruled out simply pointing a fast HTTP client at the endpoint in a loop — the limiter was counting requests and would shut us down long before exhausting a meaningful password list.

GraphQL aliases were the way around it. Aliases exist as a normal language feature for a mundane reason — letting a client request the same field twice with different arguments in one response, since a raw GraphQL response object can't contain two properties with the same key. Nothing in the spec restricts that to read-only queries; a mutation can carry as many aliased sub-operations as fit in the request body, and the server treats each one as a distinct operation to resolve, but the rate limiter downstream of it still only ever sees one arriving HTTP request:

```graphql
mutation {
  attempt0: login(input: {username: "carlos", password: "pass0"}) { token success }
  attempt1: login(input: {username: "carlos", password: "pass1"}) { token success }
  attempt2: login(input: {username: "carlos", password: "pass2"}) { token success }
}
```

That's the entire bypass. The rate limiter's unit of measurement (requests) and the application's actual unit of risk (login attempts) had come apart, and aliases are exactly the tool for exploiting that gap.

## The Exploit

We built the alias batch against PortSwigger's standard authentication password list — 100 candidate passwords — targeting the `carlos` account, and confirmed the full batch fit comfortably inside a single request at roughly 8.5KB, well under any practical body-size limit:

```json
{"query": "mutation { attempt0: login(input: {username: \"carlos\", password: \"123456\"}) { token success } attempt1: login(input: {username: \"carlos\", password: \"password\"}) { token success } ... attempt99: login(input: {username: \"carlos\", password: \"peter\"}) { token success } }"}
```

One HTTP `POST` carried all 100 attempts. The rate limiter counted it as a single request and let it through. Scanning the response for `"success": true` located the winning alias, and the password sitting next to it in the request body was `carlos`'s real credential. Logging in normally with that password solved the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the identical technique: log in with any credentials to capture the `login` mutation in Proxy history, send it to Repeater, and build an aliased batch in Repeater's GraphQL tab with each alias using `carlos` and a different password from the authentication list, ensuring every alias requests the `success` field so the outcome is visible in one response. Their walkthrough explicitly flags that constructing this by hand is impractical and recommends scripting the alias generation rather than typing each one — which is exactly the automation our approach used from the start. They also note a real Repeater-specific gotcha we didn't have to worry about: if you build the aliased query by editing a captured request, you need to strip the leftover `variables` dictionary and `operationName` field first, or the batch won't parse correctly.

This is one of the cleanest matches in the series between our approach and PortSwigger's — same vulnerability, same alias technique, same target field (`success`) used to identify the winning attempt, and their own solution independently arrives at "script this" as the practical path. The difference is simply that we started there instead of arriving at it after trying to build the batch by hand.

## What This Teaches Us

The rate limiter here wasn't broken — it did exactly what it was built to do: count requests and throttle when the count got too high. The vulnerability is that "requests" and "attempts" were never the same thing in a GraphQL API to begin with, and building a defense around the wrong unit of measurement leaves an entire dimension unguarded. The fix has to move the counting into the GraphQL layer itself — rate limiting by resolved operation count, or by a cost-analysis pass that weighs a batch of 100 aliased mutations the same as 100 separate requests, not by however many HTTP connections happened to carry them. Anywhere a GraphQL endpoint exposes a mutation with security consequences per call — login, password reset, coupon redemption — the same alias batching technique is worth testing before trusting that a request-based rate limiter is actually limiting anything.
