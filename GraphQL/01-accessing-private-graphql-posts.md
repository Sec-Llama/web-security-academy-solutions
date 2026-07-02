# Lab: Accessing private GraphQL posts

**Category:** GraphQL API vulnerabilities
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/graphql/lab-graphql-reading-private-posts

GraphQL collapses an entire API's surface into a single endpoint, which sounds like it should make access control simpler to reason about — there's only one door to guard. In practice it does the opposite: instead of an access-control check per route, an application now needs one per field, and it's trivially easy to forget that a field returning a password or a private flag needs the same protection as the endpoint that serves it. This lab is the cleanest possible demonstration of that gap: a single hidden field, exposed by the schema itself, sitting right next to the data it's supposed to protect.

## The Target

The lab is a blog. Its post-listing page pulls content through a GraphQL query rather than a REST call, hitting a `/graphql/v1` endpoint with standard `POST` requests carrying `application/json` bodies. Blog posts are addressable individually by a `getBlogPost(id: N)` query — a shape that immediately raises the same question every numeric-ID endpoint raises: what happens if we ask for an ID the UI never links to?

## The Investigation

Before touching IDs, we needed to know what fields actually exist on a blog post — guessing field names against a GraphQL schema is a bad way to spend time when the schema will usually just tell you. We sent the standard introspection query to `/graphql/v1`:

```json
{"query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }"}
```

Introspection was enabled, and it returned the full `BlogPost` type. Its field list was longer than what the rendered blog page ever uses: `id, image, title, author, date, summary, paragraphs, isPrivate, postPassword`. Two of those — `isPrivate` and `postPassword` — have no business being queryable by an unauthenticated visitor, but nothing in the schema stops it. The schema doesn't encode access control; it just describes what's queryable, and here what's queryable includes the password gate meant to protect a post that isn't publicly listed.

## The Exploit

With the field names in hand, we didn't need to guess a body or a summary field — the schema had already told us the exact names to ask for. We enumerated `getBlogPost(id: N)` sequentially:

```json
{"query": "query { getBlogPost(id: 3) { id title paragraphs author { username } isPrivate postPassword } }"}
```

Post 3 came back with `isPrivate: true` and a populated `postPassword` field — the value the lab wanted us to recover. Submitting that string as the solution answer solved the lab.

The one real lesson buried in this exploit is unglamorous but important: our first attempt at this query used a `body` field name based on what a typical blog schema might call it, and it failed silently — GraphQL doesn't guess at typos, it just returns an error for an unknown field. The fix wasn't cleverness, it was going back to the introspection output and using the exact name it gave us: `paragraphs`, not `body`. Every GraphQL exploitation step downstream of introspection should pull field names directly from the schema response rather than from assumption.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution starts from a different observation than we did: rather than introspecting first, they browse the blog with Burp running, notice that the GraphQL responses list blog posts with sequential IDs, and spot that ID 3 is conspicuously missing from the list — a strong hint that a hidden post exists at that ID before ever looking at the schema. From there they send the introspection query (via Burp's **GraphQL > Set introspection query** action) to discover the `postPassword` field, then modify the `id` variable to 3 and add `postPassword` to the query in Repeater's GraphQL tab.

The underlying vulnerability and the final query are the same as ours — the difference is which signal we followed first. PortSwigger's manual walkthrough reads the UI for the missing-ID hint before introspecting; our script went straight to introspection and then swept a small ID range (1 through 9) looking for any post carrying a populated `postPassword`, which finds the same answer without needing to first notice a gap in a rendered list. Both are variations on the same idea — a numeric ID space is worth enumerating regardless of which detail tips you off to try it.

## What This Teaches Us

The vulnerability here isn't a broken authorization check on an endpoint — there isn't one to break, because the application never wrote one for this field. GraphQL's introspection makes every field on every type discoverable by design, which is exactly what makes it powerful for legitimate API consumers and exactly what makes an unprotected sensitive field this easy to find. The fix has to happen at the resolver level, not the transport level: a field like `postPassword` needs its own access check that runs regardless of who's asking or what query shape they used to ask for it. Disabling introspection in production would have hidden this specific discovery path, but it wouldn't have fixed the underlying problem — it only would have made us work harder to find the same field by guessing.
