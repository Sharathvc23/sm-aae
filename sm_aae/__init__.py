# SPDX-License-Identifier: MIT
"""sm-aae — the Attested Action Envelope: sign, verify, and chain agent authorizations.

An Attested Action Envelope (AAE) is the atomic, signed record that an agent's
action was evaluated against a policy *before* it ran, and what the verdict was.
A denial is a first-class signed artifact, not a silent absence, and each of an
agent's envelopes points at its predecessor by hash — so an agent's authorization
history is tamper-evident and gap-detectable on its own.

Where receipts record what an agent *did*, an AAE records what an agent *may do*.

Public API::

    from sm_aae import issue_envelope, verify_envelope, envelope_hash, order_chain

    env = issue_envelope(sk_hex, agent_id="a1", verb="read", resource="doc/1",
                         params={}, policy_id="rule:0", outcome="authorized",
                         prev_hash=None, issued_at="2026-07-04T00:00:00+00:00")
    assert verify_envelope(env)
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError as _PackageNotFoundError
from importlib.metadata import version as _dist_version

from sm_aae.envelope import (
    OUTCOMES,
    Envelope,
    canonical_bytes,
    envelope_hash,
    issue_envelope,
    order_chain,
    verify_envelope,
)

# Derived from installed distribution metadata, never hand-maintained. A literal
# here is a second copy of pyproject's ``version`` with nothing comparing them —
# the shape that shipped sm-provision 0.1.0 reporting "0.0.1" and sm-authority
# 0.1.0 reporting the same wrong value from the same template. Correct today is
# not the test; it drifts at the next bump.
try:  # pragma: no cover - trivial branch, both sides asserted in tests
    __version__ = _dist_version("sm-aae")
except _PackageNotFoundError:  # running from a source tree, not installed
    __version__ = "0.0.0.dev0"

__all__ = [
    "OUTCOMES",
    "Envelope",
    "__version__",
    "canonical_bytes",
    "envelope_hash",
    "issue_envelope",
    "order_chain",
    "verify_envelope",
]
