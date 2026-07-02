# Lab: User ID controlled by request parameter, with unpredictable user IDs

**Category:** Access Control
**Difficulty:** APPRENTICE
**Lab:** https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids

Swapping a username in an `id` parameter is trivial when usernames are the identifier. Switch that
identifier to a GUID and the naive version of the attack — just guess the next value — stops
working entirely. The vulnerability doesn't go away, though; it just relocates the hard part from
"guess the ID" to "find the ID somewhere it leaked."

## The Target

Same account-page pattern as the previous lab — `/my-account?id=<identifier>` — except this
application uses opaque GUIDs instead of usernames as the identifier. The site also has a blog
section where posts are attributed to their authors, including `carlos`.

## The Investigation

An unguessable ID only stays unguessable if it's never exposed anywhere else. Blog posts attributed
to `carlos` were the obvious place to look — an author byline on a public post is exactly the kind
of feature that tends to link out to the author's profile using the same identifier the account page
expects.

We pulled the blog listing, followed links into individual posts, and searched each post's HTML for
a GUID-shaped `userId` parameter appearing near `carlos`'s name:

```
/blogs, /post?postId=N                     -- Blog posts expose author userId GUIDs
regex: userId=([a-f0-9-]{36})              -- Extract GUIDs from blog post pages
```

That surfaced `carlos`'s GUID sitting in a link on his own blog post — the "unpredictable" ID handed
straight to us by a feature that had nothing to do with account security.

## The Exploit

With the GUID in hand, we logged in as `wiener` and swapped it into the `id` parameter on the
account page, exactly as in the previous lab:

```python
resp = client.get(f"{base}/my-account", params={"id": carlos_guid})
```

The response rendered `carlos`'s account page and API key under `wiener`'s session. We extracted the
key and submitted it, solving the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's solution follows the identical logic: find a blog post by `carlos`, click through to
note his user ID from the URL, log in, and swap that ID into the `id` parameter on the account page
to retrieve and submit the API key. Same discovery source, same exploitation step.

The difference is scale, not technique — PortSwigger's walkthrough manually clicks one post by
`carlos` and reads the ID off the URL bar. Our script instead swept the blog listing and every post
it linked to, regex-matching for a GUID near `carlos`'s name across all of them, which is really
just automating the same manual lookup so it doesn't depend on knowing in advance which single post
to click.

## What This Teaches Us

Switching from sequential IDs to GUIDs raises the cost of blind guessing, but it does nothing for an
identifier that's disclosed elsewhere in the application. The account page's access control gap is
identical to the previous lab's — no check that the session owns the requested `id` — and the GUID
only changes how an attacker has to *obtain* a valid target identifier, not whether the underlying
request will honor it. Unpredictability is not a substitute for authorization; it just shifts the
attacker's work from guessing to searching.
