# Privilege escalation via server-side prototype pollution

**Category:** Server-Side Prototype Pollution
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/prototype-pollution/server-side/lab-privilege-escalation-via-server-side-prototype-pollution

Client-side prototype pollution ends at the browser tab it ran in — the worst it usually does is
pop an `alert()` or run script in the victim's own session. Move the same bug server-side and the
blast radius changes completely: a polluted `Object.prototype` on the server is shared by every
request the process handles, and if any piece of authorization logic reads a property off a plain
object without checking whether that object actually owns it, pollution becomes a privilege
escalation. This lab is the introduction to that shift — the same recursive-merge flaw as the
client-side labs in this series, but landing on a Node.js/Express backend instead of a browser.

## The Target

The application is the familiar e-commerce storefront, but the interesting surface here is the
account management flow. Updating a delivery address sends:

```
POST /my-account/change-address
Content-Type: application/json

{"address_line_1": "...", "address_line_2": "...", "city": "...", "postcode": "...", "country": "...", "sessionId": "..."}
```

The server responds with the updated user object as JSON. Login on this lab is also JSON-based —
the client-side `jsonSubmit()` helper posts credentials as a JSON body rather than a form —
which told us the backend was built around parsing and merging JSON request bodies throughout the
app, not just on one isolated endpoint.

## The Investigation

With a JSON body reaching the server and an updated object reflected straight back in the
response, the standard server-side pollution probe was to see whether an arbitrary property
survives a round trip through the merge. We added a harmless throwaway property inside `__proto__`:

```json
{"__proto__": {"foo": "bar"}}
```

The `foo` property came back in the response even though nothing in the request should legitimately
produce it — proof the server's merge logic was writing our nested object's keys onto
`Object.prototype` rather than onto the target object itself, exactly the same class of unsafe
recursive merge as the client-side labs, just running in Node instead of the DOM.

Confirming pollution was only half the job — the real question was which property, once
inherited, would actually change what the server does. This is where we had an advantage over
just guessing: the page that renders the account response filters certain fields out of the display
before showing them to the user. Reading `updateAddress.js`, we found:

```javascript
.filter(e => e[0] !== 'isAdmin')
```

That single filter line told us the raw JSON response includes an `isAdmin` field that the UI
deliberately hides — a strong signal that `isAdmin` is exactly the kind of server-side
authorization flag this lab wants pollution to reach. The user object itself doesn't set its own
`isAdmin` property, so when nothing else provides one, it falls through to whatever sits on
`Object.prototype`.

One operational detail mattered before any of this worked: the `change-address` endpoint requires
a `sessionId` value pulled from the account page's hidden form field. Omitting it returns a `400`
regardless of the JSON payload, so every pollution attempt had to carry a valid `sessionId`
alongside the polluted `__proto__` object.

## The Exploit

With the gadget identified, the working payload polluted `isAdmin` directly:

```json
{"__proto__": {"isAdmin": true}}
```

Sent to `POST /my-account/change-address` alongside the required `sessionId` and address fields,
this set `Object.prototype.isAdmin = true`. Every user object in the process — including our own —
now inherited `isAdmin: true` with nothing overriding it locally. Reloading the account area
exposed the admin panel, from which deleting user `carlos` completed the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's published solution follows an identical path: intercept `POST /my-account/change-address`
in Burp, confirm the pollution source with `"__proto__": {"foo":"bar"}` and watch for the property
appearing in the response, notice `isAdmin: false` sitting in that same response body, then flip it
with `"__proto__": {"isAdmin":true}` before refreshing the browser and using the newly visible admin
panel to delete `carlos`.

The technique matches ours exactly, including how the gadget gets identified — PortSwigger's
walkthrough spots `isAdmin: false` directly in the raw response body, while we noticed it indirectly
through the client-side filter that hides it from display. Both routes point at the same property.
As with the rest of this series, the practical difference is delivery: PortSwigger drives this
through Burp's Proxy/Repeater by hand, we sent the same requests through an automated Python client.
The underlying prototype pollution mechanics are identical either way.

## What This Teaches Us

The vulnerability here isn't really about JSON parsing — it's about what happens when authorization
logic and object-merging logic share the same prototype chain. `isAdmin` was never meant to be
attacker-controlled, but because the server merged untrusted JSON directly into objects without
guarding against `__proto__` as a key, and because the authorization check never verified `isAdmin`
was the object's *own* property rather than an inherited one, pollution turned an address-update
form into a full admin takeover. The fix is the same one that applies across this entire series:
sanitize `__proto__`/`constructor`/`prototype` out of merge keys, or better, build target objects
with `Object.create(null)` so there's no shared prototype for an attacker to reach into in the
first place.
