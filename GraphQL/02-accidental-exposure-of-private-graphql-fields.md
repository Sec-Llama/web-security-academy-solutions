# Lab: Accidental exposure of private GraphQL fields

**Category:** GraphQL API vulnerabilities
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/graphql/lab-graphql-accidental-field-exposure

The previous lab exposed a field the application never should have made queryable at all. This one is a sharper version of the same mistake: the exposed field isn't a bonus flag on a blog post, it's the `password` field on the `User` type itself, sitting in the same schema that powers login. It's a reminder that GraphQL's single-endpoint model means the object type backing your authentication system and the object type backing your public content feed can be one accidental schema decision away from sharing the same over-exposed shape.

## The Target

User management on this lab runs through the same GraphQL endpoint as everything else, `/graphql/v1`, over standard `POST`/`application/json`. The login form on the site doesn't submit to a conventional `/login` route — sending a plain form `POST` there returned `405 Method Not Allowed`, which was itself a useful signal before we ever looked at the schema: if the obvious login path refuses form submissions outright, the application is very likely routing authentication through GraphQL instead.

## The Investigation

We ran full introspection against `/graphql/v1` and got the schema back cleanly. Walking the `types` list for anything auth-shaped (`user`, `login`, `auth`, `credential`, `admin` in the type or field names) turned up a `User` type with three fields: `id`, `username`, `password`. A `password` field returned directly on the object representing every user in the system is not a subtle bug — it's the credential store itself, reachable through whichever query resolves a `User`.

The relevant query turned out to be `getUser(id: Int)`, which fetches a user by a plain numeric ID with no apparent ownership check tying the requester to that ID. We queried it directly:

```json
{"query": "query { getUser(id: 1) { id username password } }"}
```

The response returned user ID 1: `administrator`, with the password field populated in plaintext. No authentication was required to make this call — the endpoint answered the same way whether or not we were logged in.

## The Exploit

With the administrator's plaintext password in hand, the remaining problem was purely mechanical: this application authenticates through GraphQL, not a form POST, so the credential had to go back in through the same channel it came out of.

```json
{"query": "mutation { login(input: {username: \"administrator\", password: \"<recovered password>\"}) { token success } }"}
```

The mutation returned a `token`, which we set as the `session` cookie. That was enough to load the admin panel authenticated as `administrator`, from which we deleted the `carlos` account and solved the lab.

The step that would have derailed this exploit if we'd approached it as a normal web app is worth naming directly: our first instinct was to POST the recovered credentials to `/login` as a standard form submission, the way essentially every other lab in this series authenticates. That returned `405` again. The 405 wasn't a dead end — it was the same signal from the investigation phase repeating itself, confirming that authentication had to go through the `login` mutation and its token had to be applied as a cookie manually, not through a conventional login flow.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's own path to the same discovery goes through Burp's site map rather than a direct introspection query in isolation: log in with any credentials, capture the resulting GraphQL mutation in Proxy history, send it to Repeater, insert an introspection query from there, then use **GraphQL > Save GraphQL queries to site map** to let Burp catalogue every query and mutation the schema exposes. Browsing that site map surfaces the `getUser` query and its default response of `id: 0` returning nothing — from which they iterate the `id` variable until landing on `id: 1` and recovering the administrator's credentials the same way we did.

The technique is identical — introspection reveals a `password` field on `User`, `getUser` is queried across a small ID range, and the recovered plaintext credential is submitted through the `login` mutation rather than a form. The difference is tooling: PortSwigger drives this through Burp's site map and Repeater's GraphQL tab; we ran the introspection query and the `getUser` sweep directly against the endpoint. Both approaches converge on exactly the same finding because the vulnerability lives entirely in what the schema exposes, not in how the request happens to be constructed.

## What This Teaches Us

This lab makes a point the first one only implied: an over-exposed field is at its most dangerous when the object it sits on is the one backing authentication. A `password` field on `User` isn't a content leak, it's a full account takeover primitive, reachable by anyone who can reach the GraphQL endpoint at all — no session, no rate limit, no prior access required. The fix is the same principle as before, applied to higher-stakes data: sensitive fields need resolver-level authorization independent of the schema's shape, and password material specifically should never be a queryable field on any type reachable by a general-purpose query, full stop — it belongs behind the authentication mutation and nowhere else in the schema.
