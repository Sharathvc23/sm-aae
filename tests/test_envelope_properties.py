# SPDX-License-Identifier: MIT
"""Hypothesis property battery for the envelope + chain invariants."""

from __future__ import annotations

import random

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given, settings
from hypothesis import strategies as st

from sm_aae import envelope_hash, issue_envelope, order_chain, verify_envelope

_TS = "2026-07-04T00:00:00+00:00"

# JSON-serializable scalar params.
_scalars = st.one_of(st.text(max_size=8), st.integers(), st.booleans(), st.none())
_params = st.dictionaries(st.text(min_size=1, max_size=6), _scalars, max_size=4)
_idents = st.text(min_size=1, max_size=12)
_outcomes = st.sampled_from(["authorized", "denied", "conditional"])


def _key() -> str:
    return Ed25519PrivateKey.generate().private_bytes_raw().hex()


@given(agent=_idents, verb=_idents, resource=_idents, params=_params, outcome=_outcomes)
@settings(max_examples=100)
def test_round_trip_any_fields(
    agent: str, verb: str, resource: str, params: dict, outcome: str
) -> None:
    env = issue_envelope(
        _key(),
        agent_id=agent,
        verb=verb,
        resource=resource,
        params=params,
        policy_id="p",
        outcome=outcome,
        prev_hash=None,
        issued_at=_TS,
    )
    assert verify_envelope(env)
    assert len(env) == 8


@given(mutated=st.sampled_from(["agent_id", "policy_id", "outcome", "issued_at", "pubkey", "sig"]))
@settings(max_examples=60)
def test_any_single_mutation_fails(mutated: str) -> None:
    env = issue_envelope(
        _key(),
        agent_id="a",
        verb="v",
        resource="r",
        params={},
        policy_id="p",
        outcome="authorized",
        prev_hash=None,
        issued_at=_TS,
    )
    if mutated == "outcome":
        env[mutated] = "denied"
    elif mutated == "pubkey":
        env[mutated] = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    elif mutated == "sig":
        env[mutated] = "0" * 128
    else:
        env[mutated] = str(env[mutated]) + "x"
    assert not verify_envelope(env)


@given(n=st.integers(min_value=1, max_value=25), seed=st.integers(min_value=0, max_value=10_000))
@settings(max_examples=60)
def test_shuffle_recovers_unique_order(n: int, seed: int) -> None:
    sk = _key()
    envs: list[dict] = []
    prev: str | None = None
    for i in range(n):
        env = issue_envelope(
            sk,
            agent_id="a",
            verb=f"v{i}",
            resource="r",
            params={},
            policy_id="p",
            outcome="authorized",
            prev_hash=prev,
            issued_at=_TS,
        )
        envs.append(env)
        prev = envelope_hash(env)
    shuffled = list(envs)
    random.Random(seed).shuffle(shuffled)
    assert order_chain(shuffled) == envs


@given(n=st.integers(min_value=3, max_value=20), drop=st.integers(min_value=1, max_value=18))
@settings(max_examples=60)
def test_deleting_interior_link_is_detected(n: int, drop: int) -> None:
    sk = _key()
    envs: list[dict] = []
    prev: str | None = None
    for i in range(n):
        env = issue_envelope(
            sk,
            agent_id="a",
            verb=f"v{i}",
            resource="r",
            params={},
            policy_id="p",
            outcome="authorized",
            prev_hash=prev,
            issued_at=_TS,
        )
        envs.append(env)
        prev = envelope_hash(env)
    idx = 1 + (drop % (n - 2))  # an interior index in [1, n-2]
    remaining = envs[:idx] + envs[idx + 1 :]
    assert order_chain(remaining) is None
