# AAE — Attested Action Envelope — Working Draft

**Version:** v0.1 · **Status:** working draft, documents the format the reference
implementation (`sm-aae`) produces and verifies. Offered for review; not a
normative standard.

> The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, MAY are to be
> interpreted as in [RFC 2119] when in all capitals.

## 1. Scope and non-goals

### 1.1 Scope

An **Attested Action Envelope (AAE)** is the atomic, signed, machine-verifiable
record that an autonomous agent's action was evaluated against a policy at a
point in time, together with the verdict. It binds: **who** asked (`agent_id`),
**what** (`action`), **which policy decided** (`policy_id`), **the verdict**
(`outcome`), **how it links** to the agent's prior envelope (`prev_hash`),
**when** (`issued_at`), and **by whose key** (`sig` + `pubkey`).

A refusal is in scope and first-class: a `denied` verdict yields a fully signed
envelope, so "this request was refused, under this policy, at this point in the
agent's history" is provable from the envelope and its chain — not inferred from
an absence.

### 1.2 Non-goals

This specification does **not** define: how policies are written or evaluated
(the caller supplies `policy_id` and `outcome`); identity issuance or key
distribution; transport; storage or indexing; or rendering.

### 1.3 Audiences

Implementers of the envelope library; auditors verifying an agent's authorization
history; systems that gate agent actions and want a signed record of every
decision including refusals.

## 2. Relationship to other specifications

An AAE is the *per-action* complement to *per-agent* claims. Static agent facts
describe who an agent is and what it is capable of; an AAE records a **decision
taken about a specific action** at a moment in time. In the agent-evidence family
it sits alongside receipts (which record what an agent *did*, after the fact) as
the record of what an agent *may do*, decided before the fact.

## 3. The envelope (normative)

An envelope is a JSON object with **exactly** these eight members:

| Member | Type | Requirement |
|---|---|---|
| `agent_id` | string, non-empty | REQUIRED |
| `action` | object `{verb: string, resource: string, params: object}` | REQUIRED; exactly these three members |
| `policy_id` | string | REQUIRED |
| `outcome` | string, one of `authorized` \| `denied` \| `conditional` | REQUIRED |
| `prev_hash` | string (64-char lowercase hex SHA-256) or `null` | REQUIRED; `null` only for an agent's first envelope |
| `issued_at` | string, RFC 3339 timestamp | REQUIRED; supplied by the issuer, validated by parsing |
| `sig` | string (128-char hex Ed25519 signature) | REQUIRED |
| `pubkey` | string (64-char hex, raw 32-byte Ed25519 public key) | REQUIRED |

A document with any additional member, any missing member, a malformed `action`,
or an `outcome` outside the closed set is **not** an envelope and MUST fail
verification.

### 3.1 Canonicalization

The signing input is the JSON serialization of the envelope **with the `sig`
member removed**, using: keys sorted lexicographically at every level; the
compact separators `","` and `":"` (no insignificant whitespace); UTF-8
encoding. `params` values MUST be JSON-serializable. Implementations MUST produce
byte-identical canonical bytes for equal envelopes.

### 3.2 Signature

`sig` is the Ed25519 signature ([RFC 8032]) over the canonical bytes (§3.1),
hex-encoded. `pubkey` is the raw 32-byte Ed25519 public key, hex-encoded. A
verifier MUST recompute the canonical bytes and verify `sig` under `pubkey`; any
mismatch MUST yield failure, and hostile input MUST NOT raise.

### 3.3 Envelope hash and the chain

The **envelope hash** is the lowercase-hex SHA-256 ([FIPS 180-4]) of the JSON
serialization of the **full** envelope (including `sig`) under the §3.1 key
ordering and separators. A successor envelope's `prev_hash` MUST equal the
envelope hash of the agent's immediately preceding envelope. Because the hash
covers `sig`, the chain commits to the signed artifacts themselves.

## 4. Verification (normative)

A verifier of a single envelope MUST perform §3 structural validation and §3.2
signature verification.

A verifier of an agent's **chain** — an unordered set of that agent's envelopes —
MUST return the unique genesis-first ordering, or reject the set, as follows. The
set is rejected if: any envelope fails single-envelope verification; more than one
distinct `agent_id` appears (a `prev_hash` referencing another agent's envelope is
a foreign-chain splice); there is not exactly one envelope with `prev_hash = null`;
any non-null `prev_hash` names no envelope in the set (a gap, including a deleted
interior link); two envelopes share a `prev_hash` (a fork); any two envelopes are
duplicates; or the reconstructed chain does not include every envelope in the set.

## 5. Conformance

An implementation conforms if, for every envelope it accepts, an independent
implementation of §3–§4 accepts it, and vice versa. The reference implementation
is [`sm-aae`](https://github.com/Sharathvc23/sm-aae).

## 6. Versioning

This document is v0.1. Additive changes that keep every v0.1 envelope valid are
minor revisions. A change to the field set, the canonicalization, or the
signature scheme is a new major version.

## 7. References

- [RFC 2119] Key words for use in RFCs.
- [RFC 3339] Date and Time on the Internet: Timestamps.
- [RFC 8032] Edwards-Curve Digital Signature Algorithm (EdDSA).
- [FIPS 180-4] Secure Hash Standard (SHA-256).

---

Built at [labs.stellarminds.ai](https://labs.stellarminds.ai).
