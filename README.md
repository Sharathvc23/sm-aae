# AAE — Attested Action Envelope

**A signed, per-agent-chained record of a pre-action authorization verdict.**

Reputation and receipts record what an agent *did* — after the fact. An Attested
Action Envelope records what an agent *may do*: a small signed object, issued
**before** an action runs, stating who asked to do what, which policy decided,
and what the verdict was. A refusal is a first-class signed artifact — "we said
no, here, then" is provable later, not merely an absence of evidence — and each
of an agent's envelopes points at its predecessor by hash, so its authorization
history is tamper-evident and gap-detectable on its own.

sm-aae is the minimal, dependency-light library that **defines and
cryptographically verifies** that envelope. It is intentionally domain-neutral:
it applies anywhere agents act under a policy and a verifiable audit record of
*what was permitted, and what was refused* matters — enterprise workflows under
internal policy, regulated data handling, SLA-bound automation, cross-team
coordination.

## The envelope — eight fields

| Field | Meaning |
|---|---|
| `agent_id` | The acting agent's identity (whatever string your identity layer yields). |
| `action` | `{verb, resource, params}` — what the agent asked to do. |
| `policy_id` | The policy entry that produced the verdict. |
| `outcome` | `"authorized"` \| `"denied"` \| `"conditional"` — refusals are first-class. |
| `prev_hash` | Hex SHA-256 of this agent's previous envelope, or `null` for the first. |
| `issued_at` | RFC 3339 timestamp (caller-supplied). |
| `sig` | Hex Ed25519 signature over the canonical envelope minus `sig`. |
| `pubkey` | Hex of the issuer's raw 32-byte Ed25519 public key. |

Canonicalization is sorted-key, compact-separator JSON over the envelope without
`sig`. Everything is deterministic: identical inputs produce byte-identical
envelopes, and hostile input never raises out of the verifiers.

## Install

```bash
pip install sm-aae
```

Runtime dependency: [`cryptography`](https://pypi.org/project/cryptography/) only.

## Use

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sm_aae import issue_envelope, verify_envelope, envelope_hash, order_chain

sk = Ed25519PrivateKey.generate().private_bytes_raw().hex()

granted = issue_envelope(
    sk, agent_id="agent-1", verb="read", resource="doc/1", params={},
    policy_id="rule:read-allow", outcome="authorized",
    prev_hash=None, issued_at="2026-07-04T00:00:00+00:00",
)
refused = issue_envelope(
    sk, agent_id="agent-1", verb="spend", resource="treasury", params={},
    policy_id="rule:deny", outcome="denied",
    prev_hash=envelope_hash(granted), issued_at="2026-07-04T00:01:00+00:00",
)

assert verify_envelope(granted) and verify_envelope(refused)
assert order_chain([refused, granted]) == [granted, refused]  # recovers the causal order
```

`order_chain` returns the agent's envelopes genesis-first, or `None` if they
don't form exactly one intact chain — it rejects gaps (a deleted interior link),
forks, duplicates, and a `prev_hash` that reaches into another agent's chain.

## Public API

| Function | Purpose |
|---|---|
| `issue_envelope(signing_key, *, …)` | Build and sign a complete envelope. |
| `verify_envelope(candidate) -> bool` | Structural + signature check; never raises. |
| `envelope_hash(envelope) -> str` | SHA-256 of the signed envelope (what `prev_hash` points at). |
| `canonical_bytes(envelope) -> bytes` | The exact bytes the signature covers. |
| `order_chain(envelopes) -> list \| None` | The agent's unique causal chain, or `None`. |

## Where it fits

`sm-aae` is the per-action authorization primitive in a small family of agent
evidence tools:

- [**sm-arp**](https://github.com/Sharathvc23/sm-arp) — receipts: *what an agent did*.
- [**sm-parc**](https://github.com/Sharathvc23/sm-parc) — portable reputation over those receipts.
- **sm-aae** (this) — *what an agent may do*, and the refusals.

It complements NANDA's static agent facts (claims about *who an agent is*) with a
dynamic, signed record of *a decision taken about an agent's action at a moment
in time*. See [`SPEC.md`](SPEC.md) for the normative wire format,
[`WHITEPAPER.md`](WHITEPAPER.md) for the argument, and
[`THREATMODEL.md`](THREATMODEL.md) for what it does and does not defend.

## Development

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy sm_aae && coverage run -m pytest && coverage report
```

## License

MIT. See [LICENSE](LICENSE).

---

Built at [labs.stellarminds.ai](https://labs.stellarminds.ai).

*First published: 2026-07-04 | Last modified: 2026-07-04*
