# Bypassing flawed input filters for server-side prototype pollution

**Category:** Server-Side Prototype Pollution
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/prototype-pollution/server-side/lab-bypassing-flawed-input-filters-for-server-side-prototype-pollution

Once a development team notices prototype pollution is possible, the first fix reflex is usually
the same one seen on the client-side labs in this series: strip the dangerous keyword out of the
input. On the client, that meant filtering `__proto__` out of query strings. Here, the same
instinct shows up server-side — reject any JSON key literally named `__proto__` — and it fails for
the same underlying reason: `__proto__` is not the only way to reach `Object.prototype`.

## The Target

The application is the same `change-address` JSON endpoint as the previous two labs, but this time
sending our familiar pollution payload does nothing at all:

```json
{"__proto__": {"json spaces": 10}}
```

No indentation change, no behavior shift. The server was clearly inspecting incoming JSON keys and
rejecting or stripping anything named `__proto__` before the merge ever ran.

## The Investigation

A filter that blocks the literal string `__proto__` is protecting exactly one path to
`Object.prototype` — but JavaScript exposes at least one more. Every plain object also carries a
`constructor` property pointing back to its constructor function, and every constructor function
carries a `prototype` property pointing at, for ordinary objects, `Object.prototype` itself. Walking
`obj.constructor.prototype` lands in the same place as `obj.__proto__` — it's a different property
path to an identical destination, and a filter keyed on the string `__proto__` has no reason to
touch either `constructor` or `prototype` individually.

We sent the same detection payload through that alternate path:

```json
{"constructor": {"prototype": {"json spaces": 10}}}
```

This time the follow-up JSON response came back indented. The filter had done exactly what it was
built to do — block `__proto__` — while leaving the mechanically equivalent `constructor.prototype`
route completely open.

## The Exploit

With the bypass confirmed, we reused the same `isAdmin` gadget from the earlier labs in this
series, just routed through the unfiltered path:

```json
{"constructor": {"prototype": {"isAdmin": true}}}
```

Sent to `/my-account/change-address`, this set `Object.prototype.isAdmin = true` exactly as the
direct `__proto__` payload had in the first lab of this series — the filter never saw it coming
because it was never looking at `constructor` or `prototype` as keys in their own right. The
response's `isAdmin` field flipped from `false` to `true`, the admin panel appeared after a reload,
and deleting `carlos` completed the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's official walkthrough reaches the identical bypass: try `"__proto__": {"json
spaces":10}` and observe it has no effect, then switch to `"constructor": {"prototype": {"json
spaces":10}}` and observe the indentation change that proves the alternate path works. From there
they identify the same `isAdmin: false` gadget in the response and flip it with `"constructor":
{"prototype": {"isAdmin":true}}`, refresh, and delete `carlos` from the admin panel — the same
sequence and the same underlying `constructor.prototype` technique we used.

This is a case where our approach and PortSwigger's converge exactly on both the detection oracle
and the exploit payload, differing only in tooling: their walkthrough works through Burp's Proxy
and Repeater by hand, ours ran the same two JSON requests through a scripted HTTP client.

## What This Teaches Us

Filtering a single keyword out of user input is a pattern that keeps failing across this entire
lab series, and this lab is the sharpest illustration of why: `__proto__`, `constructor`, and
`prototype` are three different property names that can all be used, alone or combined, to reach
the same object. A filter has to account for every path to the destination, not just the one with
the most obviously suspicious name. The durable fix isn't a longer blocklist — it's changing how
the merge itself works, either by validating incoming keys against an explicit allowlist of
expected fields or by building the target object with `Object.create(null)` so it has no prototype
chain at all for any of these paths to reach.
