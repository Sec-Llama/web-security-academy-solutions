# Lab: Using PHAR deserialization to deploy a custom gadget chain

**Category:** Insecure Deserialization
**Difficulty:** EXPERT
**Lab:** https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-using-phar-deserialization-to-deploy-a-custom-gadget-chain

Every lab so far assumed an obvious deserialization entry point — a session cookie, decoded and
handed to `unserialize()` explicitly. This lab's entire premise is that deserialization can happen
implicitly, with no cookie involved at all, triggered by something as innocuous as checking whether
a file exists. PHP's `phar://` stream wrapper deserializes a PHAR archive's metadata the moment
almost any filesystem function touches a path using that scheme — and if an attacker can get a
PHAR file onto disk under any extension at all, that's a deserialization trigger with no cookie,
no explicit `unserialize()` call, and no obvious "this endpoint deserializes" signal anywhere in
the application's request handling.

## The Target

The application accepts a JPG avatar upload and serves it back through `/cgi-bin/avatar.php?avatar=<name>`.
Nothing about an image upload feature looks like a deserialization surface. The same `~`
editor-backup convention from the earlier PHP labs exposed source for two classes reachable from
this application, `CustomTemplate` and `Blog`, again via `/cgi-bin/CustomTemplate.php~` and
`/cgi-bin/Blog.php~`.

## The Investigation

Reading the leaked source produced a two-class gadget chain and, separately, a delivery problem to
solve. The gadget chain: `CustomTemplate.__destruct()` calls a `lockFilePath()` method that
concatenates `template_file_path`, and if that property is itself an object rather than a string,
PHP implicitly calls that object's `__toString()` during the concatenation. `Blog.__toString()`
renders `desc` through a Twig template engine — and Twig 1.x is vulnerable to server-side template
injection, meaning whatever string sits in `desc` gets evaluated as a Twig template, not just
displayed. So: `CustomTemplate.__destruct()` → string concatenation forces `Blog.__toString()` →
Twig renders attacker-controlled `desc` → SSTI → RCE. The SSTI payload itself abuses Twig's filter
registration to reach `exec()`:

```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("rm /home/carlos/morale.txt")}}
```

The delivery problem was separate: `avatar.php` calls `file_exists()` on the avatar path, and the
upload form only accepts JPG files — there's no session cookie or request parameter carrying
serialized data anywhere in this flow. The trigger is `phar://` itself: requesting
`avatar.php?avatar=phar://<username>` makes `file_exists()` invoke the `phar` stream wrapper on that
path, and the wrapper parses the file as a PHAR archive *and deserializes its metadata* as a side
effect of just checking whether it exists — with no explicit `unserialize()` call in sight. The
missing piece was getting a file PHP would accept as both a valid JPEG (to pass upload validation)
and a valid PHAR archive (to trigger the wrapper) at the same time.

We built this using the TAR-based PHAR-JPG polyglot technique (the "kunte0" method): a PHAR archive
in TAR format, embedded inside a JPEG's COM (comment) marker segment, so the same byte sequence
parses as a legitimate image to anything reading it as a JPEG and as a legitimate archive to
anything reading it through `phar://`. Constructing it required:

1. Building TAR entries in a specific required order — a dummy user file (`test.txt`) first,
   followed by `.phar/stub.php`, `.phar/.metadata.bin` (our serialized gadget chain), and
   `.phar/signature.bin`.
2. Stripping the first 6 bytes of the TAR stream (the start of the first entry's filename field)
   and prepending JPEG's SOI marker plus a COM marker and length in their place.
3. Appending the rest of a real JPEG's bytes after the TAR data.
4. Recomputing the first TAR entry's header checksum, since the byte-splicing invalidates it.
5. Encoding the PHAR metadata using *public* property syntax (`s:18:"template_file_path"`, no
   null-byte class prefix) rather than the private-property encoding used in earlier labs — the
   kunte0 tooling defines the gadget class as empty so its properties are dynamic and effectively
   public, while PHP's `__destruct()` still reaches them via `$this->template_file_path` the same
   way it would a declared property.
6. Computing a SHA1 signature over everything preceding the signature entry, packed as
   `flags (4 bytes LE) + hash_len (4 bytes LE) + SHA1 digest (20 bytes)`.

## The Exploit

The serialized metadata embedded in the polyglot's PHAR portion was:

```
O:14:"CustomTemplate":1:{s:18:"template_file_path";O:4:"Blog":2:{s:4:"desc";s:LEN:"{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"rm /home/carlos/morale.txt\")}}";s:4:"user";s:4:"user";}}
```

With the polyglot built, the exploit flow was: log in, upload the polyglot as the avatar (accepted,
since it's a structurally valid JPEG), then request
`/cgi-bin/avatar.php?avatar=phar://<username>` — the `phar://` scheme forces `file_exists()` to
invoke the PHAR stream wrapper on our uploaded file, which parses its metadata and deserializes the
embedded `CustomTemplate(Blog(...))` object graph. Garbage collection then fired
`CustomTemplate.__destruct()`, forcing the `Blog.__toString()` call, rendering our SSTI payload
through Twig, and executing `rm /home/carlos/morale.txt` — solving the lab.

## Comparing Notes: PortSwigger's Official Solution

PortSwigger's official solution traces the identical gadget chain — the same `~`-suffixed source
leak, the same `CustomTemplate.__destruct()` → string concatenation → `Blog.__toString()` → Twig
SSTI path, the same `registerUndefinedFilterCallback` / `getFilter` payload shape, and the same
`phar://` trigger via `avatar.php`'s `file_exists()` call. For the polyglot construction step
itself, their walkthrough is deliberately generic: "search for 'phar jpg polyglot'... or download a
ready-made one," rather than specifying a single required implementation.

We built ours to the specific kunte0 TAR-based technique rather than using a pre-made tool,
implementing the TAR entry ordering, the COM-segment byte splicing, and the checksum/signature
recomputation as a self-contained Python builder. This isn't a different *vulnerability* path from
PortSwigger's — it's filling in the one deliberately unspecified step of their solution with a
concrete, well-documented public technique, which is exactly the kind of choice their phrasing
invites ("search online... or use a ready-made example"). The gadget chain, the trigger mechanism,
and the resulting RCE are identical either way; only the specific bytes of the polyglot container
differ based on which known construction method produced them.

## What This Teaches Us

This lab generalizes something the earlier custom-chain labs already hinted at: deserialization
doesn't require an explicit `unserialize()` call anywhere in the request path to be exploitable.
Any PHP filesystem function — `file_exists()`, `file_get_contents()`, `fopen()`, `copy()`, and
others — triggers implicit deserialization the instant it's handed a `phar://` path, which means an
upload feature that never touches PHP's serialization functions directly can still be a full
deserialization entry point if an attacker can get a file onto disk and then get any filesystem
call to touch it through that scheme. The practical defenses are narrow and specific:
`ini_set('phar.readonly', 1)` doesn't help here since it only blocks writing new PHAR files, not
reading existing ones through the wrapper; validating uploaded file *content* rather than trusting
the extension is what actually closes this off, since a magic-byte or structure check that rejects
anything but a genuine, single-format JPEG would have caught the polyglot before it ever reached
disk. The broader lesson for anyone auditing an application for deserialization risk: the search
has to include every place a client-influenced path reaches a filesystem function, not just the
places where `unserialize()` appears literally in the source.
