# Security backport modification notice

This repository builds an independent custom Node.js runtime. It is **not**
an official Node.js binary.

The runtime starts from the public Node.js `v22.23.2` source release, whose
vendored OpenSSL basis is `3.5.7`. It applies the upstream OpenSSL security
fix for CVE-2026-14456:

`openssl/openssl@08e7756c3900bcfd77a720e7b74e27d6e4ed01a9`

The Node-specific patch is a mechanical adaptation of that official patch.
It removes only the hunk for
`doc/man3/SSL_get_value_uint.pod`, a documentation file intentionally absent
from Node's pruned vendored OpenSSL tree. No executable security-code or test
hunk is removed or rewritten. The adapted patch SHA-256 is:

`b23805accae194a81fb43f07c1fbac8fdb13a4d267ef7e687bfb800241581d01`

The runtime reports its upstream OpenSSL basis truthfully as `3.5.7`; it does
not claim to be OpenSSL `3.5.8` or an official Node.js distribution. The
generated OpenSSL headers are regenerated with Node's canonical tooling and
the resulting package carries machine-readable patch, generator, binary, and
security-test provenance.
