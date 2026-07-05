# SPDX-License-Identifier: MIT
"""Example-based and adversarial tests for the envelope + chain."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sm_aae import (
    OUTCOMES,
    canonical_bytes,
    envelope_hash,
    issue_envelope,
    order_chain,
    verify_envelope,
)


def _key() -> str:
    return Ed25519PrivateKey.generate().private_bytes_raw().hex()


def _issue(sk: str, agent: str, prev: str | None, *, verb: str = "read") -> dict:
    return issue_envelope(
        sk,
        agent_id=agent,
        verb=verb,
        resource="doc/1",
        params={},
        policy_id="rule:0",
        outcome="authorized",
        prev_hash=prev,
        issued_at="2026-07-04T00:00:00+00:00",
    )


def _chain(sk: str, agent: str, n: int) -> list[dict]:
    envs: list[dict] = []
    prev: str | None = None
    for _ in range(n):
        env = _issue(sk, agent, prev)
        envs.append(env)
        prev = envelope_hash(env)
    return envs


def test_round_trip() -> None:
    env = _issue(_key(), "a1", None)
    assert verify_envelope(env)
    assert frozenset(env) == frozenset(
        {"agent_id", "action", "policy_id", "outcome", "prev_hash", "issued_at", "sig", "pubkey"}
    )
    assert env["outcome"] in OUTCOMES


def test_denial_is_a_verifiable_receipt() -> None:
    env = issue_envelope(
        _key(),
        agent_id="a1",
        verb="spend",
        resource="treasury",
        params={},
        policy_id="rule:deny",
        outcome="denied",
        prev_hash=None,
        issued_at="2026-07-04T00:00:00+00:00",
    )
    assert verify_envelope(env)
    assert env["outcome"] == "denied"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("agent_id", "attacker"),
        ("policy_id", "rule:forged"),
        ("outcome", "denied"),
        ("issued_at", "2027-01-01T00:00:00+00:00"),
    ],
)
def test_single_field_tamper_fails(field: str, value: str) -> None:
    env = _issue(_key(), "a1", None)
    env[field] = value
    assert not verify_envelope(env)


def test_action_tamper_fails() -> None:
    env = _issue(_key(), "a1", None)
    env["action"]["resource"] = "doc/999"
    assert not verify_envelope(env)


def test_pubkey_swap_fails() -> None:
    env = _issue(_key(), "a1", None)
    env["pubkey"] = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    assert not verify_envelope(env)


def test_truncated_and_nonhex_sig_fail() -> None:
    env = _issue(_key(), "a1", None)
    good = env["sig"]
    env["sig"] = good[:-2]
    assert not verify_envelope(env)
    env["sig"] = "z" * 128
    assert not verify_envelope(env)


@pytest.mark.parametrize(
    "candidate",
    [None, 42, "not-a-dict", {}, {"agent_id": "a"}],
)
def test_malformed_input_never_raises(candidate: object) -> None:
    assert verify_envelope(candidate) is False


def test_extra_field_rejected() -> None:
    env = _issue(_key(), "a1", None)
    env["extra"] = 1
    assert not verify_envelope(env)


def test_malformed_action_rejected() -> None:
    env = _issue(_key(), "a1", None)
    env["action"] = "not-a-dict"
    assert not verify_envelope(env)
    env2 = _issue(_key(), "a1", None)
    env2["action"] = {"verb": "read"}  # missing resource/params
    assert not verify_envelope(env2)


def test_issue_rejects_bad_outcome() -> None:
    with pytest.raises(ValueError, match="unknown outcome"):
        _issue_with_outcome("banana")


def test_issue_rejects_bad_prev_hash() -> None:
    with pytest.raises(ValueError, match="prev_hash"):
        issue_envelope(
            _key(),
            agent_id="a1",
            verb="read",
            resource="r",
            params={},
            policy_id="p",
            outcome="authorized",
            prev_hash="short",
            issued_at="2026-07-04T00:00:00+00:00",
        )


def test_issue_rejects_bad_timestamp() -> None:
    with pytest.raises(ValueError, match="RFC 3339"):
        issue_envelope(
            _key(),
            agent_id="a1",
            verb="read",
            resource="r",
            params={},
            policy_id="p",
            outcome="authorized",
            prev_hash=None,
            issued_at="not-a-date",
        )


def _issue_with_outcome(outcome: str) -> dict:
    return issue_envelope(
        _key(),
        agent_id="a1",
        verb="read",
        resource="r",
        params={},
        policy_id="p",
        outcome=outcome,
        prev_hash=None,
        issued_at="2026-07-04T00:00:00+00:00",
    )


def test_canonical_bytes_excludes_sig() -> None:
    env = _issue(_key(), "a1", None)
    assert b'"sig"' not in canonical_bytes(env)


def test_chain_of_three_orders_and_verifies() -> None:
    sk = _key()
    envs = _chain(sk, "a1", 3)
    ordered = order_chain(list(reversed(envs)))
    assert ordered == envs


def test_empty_chain() -> None:
    assert order_chain([]) == []


def test_chain_gap_detected() -> None:
    sk = _key()
    envs = _chain(sk, "a1", 3)
    assert order_chain([envs[0], envs[2]]) is None  # missing interior link


def test_chain_fork_detected() -> None:
    sk = _key()
    genesis = _issue(sk, "a1", None)
    h = envelope_hash(genesis)
    child_a = _issue(sk, "a1", h, verb="read")
    child_b = _issue(sk, "a1", h, verb="write")
    assert order_chain([genesis, child_a, child_b]) is None


def test_chain_duplicate_detected() -> None:
    sk = _key()
    env = _issue(sk, "a1", None)
    assert order_chain([env, dict(env)]) is None


def test_chain_multi_genesis_detected() -> None:
    sk = _key()
    assert order_chain([_issue(sk, "a1", None), _issue(sk, "a1", None, verb="write")]) is None


def test_foreign_agent_splice_rejected() -> None:
    sk = _key()
    a_genesis = _issue(sk, "alice", None)
    b_child = _issue(sk, "bob", envelope_hash(a_genesis))
    assert order_chain([a_genesis, b_child]) is None


def test_replayed_envelope_out_of_sequence_detected() -> None:
    sk = _key()
    envs = _chain(sk, "a1", 3)
    # Re-present envs[1] a second time as if it also followed envs[2].
    replayed = [envs[0], envs[1], envs[2], dict(envs[1])]
    assert order_chain(replayed) is None


def test_chain_with_an_invalid_envelope_is_none() -> None:
    sk = _key()
    envs = _chain(sk, "a1", 2)
    envs[1]["agent_id"] = "tampered"
    assert order_chain(envs) is None
