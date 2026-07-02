# Lab: Finding a hidden GraphQL endpoint

**Category:** GraphQL API vulnerabilities
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/graphql/lab-graphql-find-the-endpoint

The first two labs assumed the hard part was already done — we knew where the GraphQL endpoint lived and just had to work out what the schema was hiding. This lab strips that assumption away on two fronts at once: the endpoint isn't linked from anywhere the UI reaches, and once found, it actively tries to block the introspection query that would normally hand us the schema for free. Both defenses turn out to be built on the same kind of mistake — treating a request's surface shape as a reliable signal, when GraphQL's syntax gives an attacker room to change that shape without changing its meaning.

## The Target

User management functionality clearly exists in this application — there's an admin concept, a `carlos` account to worry about — but no page in the site links to the GraphQL endpoint that powers it. Whatever is serving those operations has to be found by direct probing rather than by clicking through the app.

## The Investigation

We swept an extended list of candidate paths — the standard set (`/graphql`, `/api`, `/api/graphql`, `/graphql/api`, `/graphql/graphql`, `/graphql/v1`, `/api/v1/graphql`) plus additional guesses like `/gql`, `/query`, `/v1/graphql`, `/v2/graphql`, `/graphiql`, `/playground`, `/console` — sending the universal probe query `{__typename}` as a `POST` to each. Nothing answered. That ruled out the assumption that this endpoint follows the usual `POST`-based convention at all, so we went back over the same path list checking `GET` requests instead. `/api` responded to `GET` with `{"data": {"__typename": "query"}}` — this endpoint runs in reverse of the typical pattern: `POST` to it returns `405 Method Not Allowed`, and it only speaks GraphQL over `GET`.

With the endpoint located, the next probe was introspection — and it came back blocked, with an explicit error: *"GraphQL introspection is not allowed, but the query contained `__schema` or `__type`."* That phrasing gives away the mechanism directly: this isn't a genuine capability restriction, it's a regex or substring filter matching the literal token `__schema{` in the request text. A filter that pattern-matches request syntax rather than evaluating what the query actually resolves to is a defense with an inherent gap — GraphQL's parser doesn't care about whitespace between a field name and its opening brace, but a naive regex checking for `__schema{` as a contiguous string absolutely does.

We inserted a newline immediately after `__schema`:

```
query { __schema
{ queryType { name } mutationType { name } types { ...FullType } } }
```

That single character change was enough. The query is still syntactically valid GraphQL — the parser ignores the whitespace — but it no longer matches the filter's `"__schema{"` pattern, since there's now a newline sitting between the two tokens. The response came back with the full schema: `getUser(id: Int) -> User { id, username }` and a `deleteOrganizationUser(input: {id: Int})` mutation.

## The Exploit

Two things about this schema stood out immediately. First, `deleteOrganizationUser` takes only an `id` — no confirmation, no secondary check visible in the schema. Second, and more seriously, this entire endpoint had shown zero authentication requirement at any point in the investigation; every probe so far, including the ones that returned real data, had gone out with no session or credential attached.

We used `getUser(id: N)` to find `carlos`'s numeric ID (3), then executed the delete mutation — over `GET`, since that's the only method this endpoint accepts:

```
GET /api?query=mutation { deleteOrganizationUser(input: { id: 3 }) { user { id } } }
```

The mutation succeeded and the lab solved. There was no authentication step anywhere in this chain — not because we bypassed one, but because none existed. A destructive, unauthenticated mutation reachable via a plain `GET` request is about as bad as a GraphQL misconfiguration gets: it's trivially cacheable, trivially linkable, and triggerable by anything that can get a victim's browser to load a URL, which is a CSRF problem layered directly on top of the missing-auth problem.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution reaches the same endpoint and the same bypass through Burp's tooling rather than a raw path sweep: probing common suffixes in Repeater, noticing that `GET /api` returns a distinct "Query not present" error (rather than a generic 404) as the hint that something GraphQL-shaped lives there, then confirming with the universal query as a URL parameter. For the introspection bypass, their solution frames it slightly more generally than "insert a newline" — it notes that developers filtering on the literal `__schema{` substring can be defeated by any character GraphQL's parser ignores but a naive regex doesn't: spaces, commas, or newlines all work, and their example uses a newline just as ours did. The exploitation step is identical to ours: locate `deleteOrganizationUser`, and send it a `GET` request with `id: 3`.

This is a case where our approach and PortSwigger's converge almost exactly on both discovery and bypass, with the same real difference that shows up throughout this series — theirs is driven through Burp's Repeater and site map by hand, ours through direct HTTP requests. The one point worth calling out: PortSwigger's writeup treats the newline as one example of a broader bypass class (any GraphQL-ignorable whitespace character defeats a literal substring filter), which is the more useful way to internalize the technique than memorizing the specific newline payload.

## What This Teaches Us

Two independent defenses failed here, and they failed for related reasons. Hiding an endpoint by omitting it from the UI is not access control — it's obscurity, and a short list of common GraphQL path conventions defeated it in a handful of requests. Blocking introspection with a substring or regex match against request text is not a schema-level control either — it's a syntax-level filter trying to stand in for one, and GraphQL's tolerance for insignificant whitespace gives an attacker a free way around any filter that isn't parsing the query the same way the GraphQL engine itself does. Underneath both of those, the actual vulnerability — a destructive mutation with no authentication check — was never touched by either defense in the first place. Obscurity and pattern-matching are not substitutes for an authorization check enforced in the resolver; this lab is what happens when a team builds the former and skips the latter.
