# SPDX-License-Identifier: MIT
"""Smoke test: import the public API and run one end-to-end flow."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import sm_aae
from sm_aae import envelope_hash, issue_envelope, order_chain, verify_envelope


def test_version_exposed() -> None:
    assert sm_aae.__version__ == "0.1.0"


def test_end_to_end_issue_verify_chain() -> None:
    sk = Ed25519PrivateKey.generate().private_bytes_raw().hex()
    first = issue_envelope(
        sk,
        agent_id="agent-1",
        verb="read",
        resource="doc/1",
        params={},
        policy_id="rule:0",
        outcome="authorized",
        prev_hash=None,
        issued_at="2026-07-04T00:00:00+00:00",
    )
    second = issue_envelope(
        sk,
        agent_id="agent-1",
        verb="spend",
        resource="treasury",
        params={"amount": 10},
        policy_id="rule:deny",
        outcome="denied",
        prev_hash=envelope_hash(first),
        issued_at="2026-07-04T00:01:00+00:00",
    )
    assert verify_envelope(first)
    assert verify_envelope(second)
    assert order_chain([second, first]) == [first, second]
