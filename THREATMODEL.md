# Threat model

What an Attested Action Envelope defends, and — just as important — what it does
not. sm-aae is a record format and its verifier; it makes narrow, checkable
guarantees and states its boundaries plainly.

## What it defends

**Field tampering.** The signature covers the canonical bytes of every field
except `sig` itself. Altering `agent_id`, `action` (any of `verb`/`resource`/
`params`), `policy_id`, `outcome`, `prev_hash`, `issued_at`, or swapping `pubkey`
invalidates the signature. `verify_envelope` returns `False`; it never raises on
hostile input.

**Structural forgery.** A document with extra fields, missing fields, a malformed
`action`, a non-hex or wrong-length `sig`/`pubkey`, an out-of-set `outcome`, or an
unparseable `issued_at` is not an envelope and fails verification.

**History tampering within an agent's chain.** `order_chain` reconstructs an
agent's unique causal order and rejects the set on:
- a **gap** — a `prev_hash` naming an envelope not present, i.e. a deleted or
  withheld interior decision;
- a **fork** — two envelopes claiming the same predecessor;
- a **foreign-chain splice** — a `prev_hash` reaching into another agent's chain
  (more than one `agent_id` in the set);
- **duplicates**, or **zero/multiple genesis** envelopes.

Because `prev_hash` commits to the predecessor's full signed bytes, swapping a
signature anywhere breaks every later link.

## What it does NOT defend — stated boundaries

**Key pinning is out of scope.** Chain integrity is by *hash commitment*, not by
binding an agent to a fixed key. An envelope self-verifies against its own
embedded `pubkey`; `order_chain` does not check that an agent used the same key
throughout. Catching an agent that re-signs its own *latest* envelope under a
fresh key requires an external "expected key for this agent" check — an identity
layer's responsibility, deliberately not this library's. Interior and foreign
tampering are still caught (they break hash links); a re-signed tip under a new
key is not, by design.

**Replay of a valid envelope.** An envelope is a record of a decision that was
made; presenting it again is not forgery. Consumers that derive side effects from
envelopes MUST track which they have already acted on. Out-of-sequence replay
*within a chain* is caught by `order_chain` (it manifests as a fork or duplicate);
standalone replay across contexts is the consumer's concern.

**Policy correctness.** sm-aae signs whatever `outcome` and `policy_id` the caller
supplies. It does not evaluate policy and cannot attest that the verdict was the
*right* one — only that it was decided, by the holder of `pubkey`, at `issued_at`,
and recorded immutably.

**Timestamp truth.** `issued_at` is validated as well-formed RFC 3339 but is
caller-asserted. sm-aae does not provide a trusted clock.

**Key custody and revocation.** Generation, storage, rotation, and revocation of
the signing key are out of scope.

## Determinism note

Equal inputs produce byte-identical envelopes (sorted-key compact JSON,
deterministic Ed25519, caller-supplied time). This is a correctness property, not
a security one, but it is what lets two independent implementations agree
byte-for-byte and lets a chain be reproduced exactly.

---

Built at [labs.stellarminds.ai](https://labs.stellarminds.ai).
