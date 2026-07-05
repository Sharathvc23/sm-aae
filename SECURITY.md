# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately via GitHub's **Report a vulnerability**
button (Security → Advisories) on this repository, or by opening a minimal issue
that says a private report is needed without disclosing details. Please do not
open a public issue describing an exploit before a fix is available.

Include, where possible: affected version, a minimal reproduction, and the impact
you observed. We aim to acknowledge within a few days.

## Scope

sm-aae is a record format and its verifier. In-scope reports include: an envelope
that verifies despite tampering; a chain defect (gap, fork, foreign-chain splice)
that `order_chain` accepts; input that causes `verify_envelope` or `order_chain`
to raise instead of returning a value; and canonicalization or signature-handling
bugs.

Out of scope (documented boundaries — see [`THREATMODEL.md`](THREATMODEL.md)):
key custody, rotation, and revocation; policy correctness; timestamp truthfulness;
and key-pinning across a chain, which is an identity layer's responsibility.

## Supported versions

The latest `0.x` release receives security fixes.
