# SPDX-License-Identifier: MIT
"""A tiny policy loop that issues authorized and denied envelopes and chains them.

A denial is a signed envelope exactly like a grant, so the refusal is provable
from the chain rather than being a silent absence. Run:

    python examples/authorize_and_deny.py
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sm_aae import envelope_hash, issue_envelope, order_chain, verify_envelope

# A minimal declarative policy: (verb, resource) -> outcome. First match wins;
# anything unlisted is denied by default. This lives in the example, not the
# library — sm-aae signs and chains verdicts; deciding them is the caller's job.
POLICY: dict[tuple[str, str], str] = {
    ("read", "doc/1"): "authorized",
    ("spend", "treasury"): "denied",
}
REQUESTS = [("read", "doc/1"), ("spend", "treasury"), ("delete", "doc/1")]


def decide(verb: str, resource: str) -> tuple[str, str]:
    """Return (policy_id, outcome) — deny-by-default for anything unlisted."""
    outcome = POLICY.get((verb, resource), "denied")
    policy_id = f"rule:{verb}:{resource}" if (verb, resource) in POLICY else "rule:default-deny"
    return policy_id, outcome


def main() -> None:
    signing_key = Ed25519PrivateKey.generate().private_bytes_raw().hex()
    envelopes: list[dict] = []
    prev: str | None = None
    for i, (verb, resource) in enumerate(REQUESTS):
        policy_id, outcome = decide(verb, resource)
        env = issue_envelope(
            signing_key,
            agent_id="agent-1",
            verb=verb,
            resource=resource,
            params={},
            policy_id=policy_id,
            outcome=outcome,
            prev_hash=prev,
            issued_at=f"2026-07-04T00:0{i}:00+00:00",
        )
        envelopes.append(env)
        prev = envelope_hash(env)
        print(f"{outcome:>11}  {verb} {resource}  ({policy_id})")

    assert all(verify_envelope(e) for e in envelopes)
    ordered = order_chain(list(reversed(envelopes)))
    assert ordered == envelopes
    denials = [e for e in envelopes if e["outcome"] == "denied"]
    print(
        f"\nchain of {len(envelopes)} verifies; "
        f"{len(denials)} refusal(s) recorded as signed receipts."
    )


if __name__ == "__main__":
    main()
