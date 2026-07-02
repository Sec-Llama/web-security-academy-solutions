# Detecting server-side prototype pollution without polluted property reflection

**Category:** Server-Side Prototype Pollution
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/prototype-pollution/server-side/lab-detecting-server-side-prototype-pollution-without-polluted-property-reflection

The previous lab's detection method relied on a lucky property: the polluted key came straight back
in the JSON response. Real targets are rarely that generous — a server can merge attacker input
into `Object.prototype` and never once show that specific property back to the client. This lab
strips that convenience away on purpose. The pollution is just as real, but proving it exists
means finding a signal that doesn't depend on the application choosing to echo our data back to us.

## The Target

Same application shape as the previous lab: `POST /my-account/change-address` accepts a JSON body
and unsafely merges it into a server-side object. This time, though, injecting an arbitrary test
property produces no trace of it anywhere in the response. The pollution mechanism hadn't changed —
only the visibility of its effects had.

## The Investigation

Our first probe was the same one that worked a lab ago:

```json
{"__proto__": {"foo": "bar"}}
```

No `foo` anywhere in the response. That ruled out reflection as a detection channel here, which
meant the only path left was to pollute a property that changes *behavior* rather than *output* —
something the Express framework itself reads internally, independent of anything the application
code chooses to display.

Express gives `res.json()` its indentation behavior from a setting called `json spaces` —
internally it calls `JSON.stringify(data, null, spaces)`. Under normal conditions the app's JSON
responses come back minified, with no whitespace between keys. If we could pollute
`Object.prototype["json spaces"]`, every subsequent JSON response from the server should suddenly
gain visible indentation, regardless of which endpoint served it:

```json
{"__proto__": {"json spaces": 10}}
```

Sending that to `change-address` and then requesting any ordinary JSON endpoint confirmed it: the
previously minified response came back with ten spaces of indentation. That's not something the
application's own code decides per-request — it's Express's internal formatting behavior reacting
to a property that only exists because we put it on the prototype. Pollution confirmed, with zero
reliance on any property being echoed back to us.

We also had two other blind oracles available for exactly this situation, documented as
alternatives for cases where `json spaces` isn't usable: polluting `status` to a value like `555`
and then deliberately breaking the request (malformed JSON, wrong content type) to force an error
response — the framework's own error handler picks up the polluted status code — and polluting
`content-type` to something like `application/json; charset=utf-7` to observe an encoding shift.
Both work on the same principle: pollute a property the framework itself consumes, then watch for
a change in behavior that has nothing to do with what the application intentionally returns.

Detection alone doesn't solve the lab — the same `isAdmin` gadget from the previous lab was still
sitting there. Once blind pollution was confirmed, we polluted `isAdmin: true` the same way,
reloaded the account area, and used the now-visible admin panel to delete `carlos`.

## The Exploit

The working detection-and-exploit chain:

1. `{"__proto__": {"json spaces": 10}}` to `/my-account/change-address` — confirmed via visibly
   indented JSON on a follow-up request.
2. `{"__proto__": {"isAdmin": true}}` to the same endpoint — the same privilege-escalation gadget
   from the previous lab, now reached without ever seeing the property reflected.
3. Admin panel access, delete `carlos`.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's published solution reaches the same conclusion — that a non-reflected property still
needs a framework-level oracle — but drives it through the `status` code technique specifically,
not `json spaces`. Their steps: send `"__proto__": {"foo":"bar"}` and confirm it doesn't reflect,
deliberately break the JSON to trigger an error response and note its `status` property is `400`,
then pollute `"__proto__": {"status":555}` and break the JSON again — the error response's `status`
and `statusCode` fields now read `555`, proving the pollution reached Express's own error-handling
object.

We used `json spaces` as our primary detection technique and had `status` documented as an
alternative — PortSwigger's walkthrough uses `status` as the primary path. Both are the same
underlying idea (pollute an Express-internal configuration property and watch for a framework-level
behavior change instead of an application-level one), just choosing a different internal property
as the oracle. Either one proves the same thing, which is part of the lesson here: once you know to
look for framework config properties instead of application data properties, there's more than one
usable signal.

## What This Teaches Us

"The polluted property doesn't show up in the response" is not the same as "the pollution didn't
work" — it just means the application layer isn't the thing reading that property back to you. Web
frameworks carry their own internal configuration on plain objects too, and those configuration
reads happen regardless of what the application developer intended to expose. Treating `json
spaces`, `status`, and `content-type` as detection oracles generalizes well beyond this one lab:
any time direct reflection isn't available, the next question is what the underlying framework
itself consumes from the same polluted prototype, silently, on every request.
