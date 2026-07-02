# Lab: Arbitrary object injection in PHP

**Category:** Insecure Deserialization
**Difficulty:** PRACTITIONER
**Lab:** https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-arbitrary-object-injection-in-php

Every lab so far has tampered with an object the application already sends us. This one is the
first real step up: instead of editing an existing object's fields, we construct an entirely
different class from scratch — one the application never intended to appear in that cookie at all
— and rely on PHP silently instantiating it and running its lifecycle methods anyway. That's the
essence of "arbitrary object injection": `unserialize()` doesn't care whether the class name it's
given is the one the developer expected.

## The Target

The same session-cookie mechanism as the earlier labs, but this application also references a
template file, `/libs/CustomTemplate.php`, somewhere in its client-facing behavior. PHP source
files aren't normally readable over HTTP, but editors routinely leave backup copies behind with a
trailing `~`, and this application's deployment left exactly that kind of artifact reachable.

## The Investigation

Requesting `/libs/CustomTemplate.php~` (the tilde-suffixed editor backup convention) returned the
raw PHP source instead of executing it — the `.php~` extension isn't mapped to the PHP interpreter,
so the web server serves it as plain text. That source revealed the `CustomTemplate` class and its
`__destruct()` magic method, which PHP invokes automatically when an object is garbage-collected —
including objects that were just deserialized and never explicitly used again. `__destruct()`
called `unlink($this->lock_file_path)`, deleting whatever file that property pointed to, with no
validation of the path. Nothing about the session mechanism restricted *which* class could be
deserialized into the cookie — the application's `unserialize()` call would happily construct any
class PHP knew about, including one we picked specifically because its destructor does something
destructive.

`lock_file_path` is declared as a private property on `CustomTemplate`, and PHP's serialization
format encodes private properties differently from public ones: instead of a plain
`s:LEN:"property_name"`, private properties are serialized with the declaring class name
null-byte-wrapped into the property name itself — `\x00ClassName\x00property_name` — and the
length prefix has to count those extra bytes. Getting this encoding exactly right (bytes, not a
string approximation) was the difference between a payload PHP would actually accept as a
well-formed `CustomTemplate` object and one that would fail to unserialize at all.

## The Exploit

We built the raw serialized bytes directly, computing the private-property name length as
30 bytes (`\x00CustomTemplate\x00lock_file_path` — 1 + 14 + 1 + 14):

```
O:14:"CustomTemplate":1:{s:30:"\x00CustomTemplate\x00lock_file_path";s:23:"/home/carlos/morale.txt";}
```

Base64-encoding these raw bytes (not a string re-encoding of an escaped representation — the
literal null bytes had to survive into the base64 input) and sending the result as the session
cookie was enough: any page load that deserializes the session cookie triggers `__destruct()` on
garbage collection, and `lock_file_path` pointed the resulting `unlink()` straight at
`/home/carlos/morale.txt`, deleting it and solving the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's published solution finds the same source leak the same way — appending `~` to
`/libs/CustomTemplate.php` — and identifies the same `__destruct()` → `unlink($this->lock_file_path)`
sink. Where it differs from what we did is the serialized string they show as the payload:
`O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}` — a plain
`s:14:"lock_file_path"` property name, with no null-byte class-name prefix and no adjustment to the
length for it.

That's a real, worth-explaining divergence, and the most likely explanation is the tooling rather
than the target: PortSwigger's walkthrough builds this payload through Burp's Inspector panel,
which understands PHP's private-property serialization rules internally and silently applies the
correct `\x00ClassName\x00` encoding when you set a property value through its GUI, even though the
panel displays the property under its plain name for readability. We didn't have that abstraction
available — constructing the payload as raw bytes in a script meant we had to reproduce PHP's
actual private-property wire format ourselves, null bytes and adjusted length prefix included, or
the object would have failed to deserialize. Both payloads describe the same logical object; only
ours reflects the literal bytes PHP's serializer would produce for a private property, which is
what a script-based approach requires and a GUI-mediated approach can hide from the user.

## What This Teaches Us

This lab is the first one where the vulnerability isn't really about a specific field's value at
all — it's about the deserializer accepting an attacker-chosen *class* in the first place.
`unserialize()` with no allowlist of expected classes means any class with an interesting magic
method anywhere in the application's autoloaded codebase is a candidate gadget, whether or not it
was ever meant to touch the session mechanism. PHP's own documentation recommends
`unserialize($data, ['allowed_classes' => [...]])` for exactly this reason — restrict deserialization
to a known-safe set of classes so `__destruct()`, `__wakeup()`, and friends can't fire on attacker-
chosen objects at all. The private-property encoding detail is a smaller but genuinely useful
takeaway for anyone building these payloads by hand: PHP's serialization format silently changes
shape based on property visibility, and getting that wrong produces a payload that looks
plausible but simply won't deserialize.
