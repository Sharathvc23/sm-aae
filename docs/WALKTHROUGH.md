# Walkthrough

A five-minute tour of sm-aae: issue a verdict, verify it, chain two, and catch a
tamper.

## 1. Install

```bash
pip install sm-aae          # runtime: cryptography only
# or, from a clone:
pip install -e ".[dev]"
```

## 2. Issue and verify one envelope

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sm_aae import issue_envelope, verify_envelope

sk = Ed25519PrivateKey.generate().private_bytes_raw().hex()

env = issue_envelope(
    sk,
    agent_id="agent-1",
    verb="read", resource="doc/1", params={},
    policy_id="rule:read-allow",
    outcome="authorized",
    prev_hash=None,                       # first envelope for this agent
    issued_at="2026-07-04T00:00:00+00:00",  # you supply the time
)

assert verify_envelope(env)
```

`issue_envelope` is the only way to mint an envelope; it validates the outcome,
the `prev_hash` shape, and the timestamp, then signs the canonical bytes.

## 3. A denial is a receipt

```python
from sm_aae import envelope_hash

refused = issue_envelope(
    sk,
    agent_id="agent-1",
    verb="spend", resource="treasury", params={"amount": 100},
    policy_id="rule:deny",
    outcome="denied",
    prev_hash=envelope_hash(env),          # links to the previous envelope
    issued_at="2026-07-04T00:01:00+00:00",
)

assert verify_envelope(refused)
assert refused["outcome"] == "denied"      # a signed refusal, not a silent gap
```

## 4. Reconstruct the chain

`order_chain` takes an agent's envelopes in any order and returns them
genesis-first — or `None` if they don't form exactly one intact chain.

```python
from sm_aae import order_chain

assert order_chain([refused, env]) == [env, refused]
```

## 5. Catch a tamper

Any change to any field breaks the signature; deleting an interior link breaks
the chain.

```python
bad = dict(env)
bad["action"] = {**bad["action"], "resource": "doc/secret"}
assert not verify_envelope(bad)            # signature no longer matches

# a missing interior envelope is detected as a gap:
third = issue_envelope(
    sk, agent_id="agent-1", verb="read", resource="doc/2", params={},
    policy_id="rule:read-allow", outcome="authorized",
    prev_hash=envelope_hash(refused), issued_at="2026-07-04T00:02:00+00:00",
)
assert order_chain([env, third]) is None   # 'refused' is missing between them
```

## 6. Runnable examples

```bash
python examples/sign_and_verify.py      # issue, verify, show a tamper failing
python examples/authorize_and_deny.py   # a small policy loop; refusals chained as receipts
```

That is the whole surface: `issue_envelope`, `verify_envelope`, `envelope_hash`,
`canonical_bytes`, `order_chain`. See [`SPEC.md`](../SPEC.md) for the normative
format and [`THREATMODEL.md`](../THREATMODEL.md) for the guarantees and their
boundaries.
