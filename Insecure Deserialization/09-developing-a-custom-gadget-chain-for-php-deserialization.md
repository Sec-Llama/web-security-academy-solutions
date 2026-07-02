# Lab: Developing a custom gadget chain for PHP deserialization

**Category:** Insecure Deserialization
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-developing-a-custom-gadget-chain-for-php-deserialization

PHPGGC solved the previous PHP lab because Symfony's gadget chain was already catalogued. This lab
removes that catalog entirely: no framework-level chain applies, and reaching code execution means
reading the application's own classes, tracing how one magic method's side effect feeds into the
next class's magic method, and hand-assembling an object graph that walks that path in the right
order.

## The Target

The same session-cookie deserialization mechanism as the earlier PHP labs, with source code again
recoverable via the `~` editor-backup convention — this time exposing not just `CustomTemplate` but
also `Product` and `DefaultMap`, three classes that, read independently, don't look dangerous at
all.

## The Investigation

Reading the leaked source revealed a chain spread across three separate classes, each one's
"exit" feeding directly into the next class's magic-method "entry":

1. `CustomTemplate.__wakeup()` — invoked automatically as soon as the object is deserialized —
   calls `build_product()`, which constructs `new Product($desc_type, $desc)` using two of
   `CustomTemplate`'s own properties.
2. `Product.__construct()` accesses `$desc->$desc_type` — a *dynamic* property access, where
   `$desc_type` (a string we control) names which property to read off `$desc` (an object we also
   control).
3. If `$desc` is a `DefaultMap` instance, that dynamic property access triggers `DefaultMap`'s
   `__get($name)` magic method, which PHP calls automatically whenever code tries to read a
   property that doesn't actually exist on the object. `DefaultMap.__get()` then calls
   `call_user_func($this->callback, $name)` — invoking whatever function name `$callback` holds,
   passing `$name` (the property name that was "read") as its argument.

The chain resolves to `call_user_func($callback, $name)`. If `$callback` is the string `"exec"`,
this becomes `exec($name)` — arbitrary command execution, where `$name` is literally the property
name `Product.__construct()` tried to read off the `DefaultMap`. That's the trick that makes the
whole chain work: we don't need a property named after our command, we need `$desc_type` (the
"property name" being accessed) to *be* our command string in the first place.

## The Exploit

We built the object graph as raw PHP-serialized bytes, again using private-property null-byte
encoding since all three classes declare their relevant fields as private:

```
O:14:"CustomTemplate":2:{
  s:33:"\x00CustomTemplate\x00default_desc_type";s:26:"rm /home/carlos/morale.txt";
  s:20:"\x00CustomTemplate\x00desc";
  O:10:"DefaultMap":1:{s:20:"\x00DefaultMap\x00callback";s:4:"exec";}
}
```

`default_desc_type` — the value `Product.__construct()` treats as the property name to read off
`desc` — is set directly to the shell command `rm /home/carlos/morale.txt`; `desc` is a nested
`DefaultMap` object whose `callback` property is the string `exec`. Base64-encoded and sent as the
session cookie, deserialization triggers `CustomTemplate.__wakeup()`, which builds a `Product`,
which triggers the dynamic property read on the `DefaultMap`, which triggers `__get()`, which calls
`exec("rm /home/carlos/morale.txt")` — deleting the target file and solving the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's official solution traces the identical three-class chain — `CustomTemplate.__wakeup()`
building a `Product`, `Product`'s constructor triggering `DefaultMap.__get()` via dynamic property
access, `call_user_func()` resolving to `exec()` — and lands on functionally the same payload
structure: `default_desc_type` set to the command string, `desc` set to a `DefaultMap` with
`callback` set to `"exec"`.

Where the official write-up's shown payload differs cosmetically is again in property-name display:
`O:14:"CustomTemplate":2:{s:17:"default_desc_type";s:26:"rm /home/carlos/morale.txt";s:4:"desc";O:10:"DefaultMap":1:{s:8:"callback";s:4:"exec";}}`
shows plain property names with no null-byte class prefix, the same simplification seen in the
arbitrary-object-injection lab, and for the same reason — Burp Inspector applies PHP's private-
property wire encoding automatically when a payload is built through its GUI, so the write-up can
show the human-readable property name without showing the underlying bytes. Our script constructs
those bytes explicitly, since there's no Inspector-equivalent abstraction available when building
the payload programmatically. The gadget chain logic itself — which is the actual expert-level
content of this lab — is identical between the two approaches.

## What This Teaches Us

This lab is the clearest illustration in the whole series of what "gadget chain" actually means:
no single class here is dangerous on its own. `CustomTemplate.__wakeup()` just builds an object.
`Product.__construct()` just reads a property. `DefaultMap.__get()` just calls a configurable
function. Each step, read in isolation during a code review, looks like ordinary application logic
— dynamic dispatch patterns are common and not inherently unsafe. The vulnerability only exists in
the composition: three independently-reasonable pieces of code, chained together by an attacker who
controls every value flowing between them via deserialization. This is exactly why allowlisting
deserializable classes (`unserialize()`'s `allowed_classes` option) is the recommended PHP fix
rather than trying to audit every magic method individually for "is this dangerous" — the danger
isn't in any one method, it's in letting an attacker choose the entire object graph and wire
arbitrary classes together in ways no single class's author ever anticipated.
