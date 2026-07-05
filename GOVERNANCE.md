# Governance

## Scope

| In scope | Out of scope |
| --- | --- |
| the eight-field envelope, its canonicalization + Ed25519 signature, and per-agent chain verification | policy authoring/evaluation (the caller supplies `policy_id` + `outcome`), identity issuance + key custody + revocation, transport, storage, rendering |

The primitive owns one thing — a signed, checkable record of a pre-action verdict
and its place in an agent's history. Anything outside the table belongs to a
companion package or the consumer.

## Versioning

Semantic Versioning 2.0.0. The envelope field set, the canonicalization, and the
signature scheme are frozen within a major version; a change requires a PR to
[`SPEC.md`](SPEC.md) before code.

## Conformance

The test suite under `tests/` is the authoritative behavioral specification. A
change in behavior without a corresponding test change is a bug. Two
implementations conform when each accepts the other's envelopes (see SPEC §5).

## Changes

Open an issue or PR. Behavioral changes must update `SPEC.md` and the tests in the
same PR. The `main` branch is always green under the full local CI contract
(`ruff check` · `ruff format --check` · `mypy` · `coverage run -m pytest`).

---

Built at [labs.stellarminds.ai](https://labs.stellarminds.ai).
