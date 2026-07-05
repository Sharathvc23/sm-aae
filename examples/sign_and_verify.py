# SPDX-License-Identifier: MIT
"""Issue an envelope, verify it, and detect a tamper. Run: python examples/sign_and_verify.py"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sm_aae import issue_envelope, verify_envelope


def main() -> None:
    signing_key = Ed25519PrivateKey.generate().private_bytes_raw().hex()
    env = issue_envelope(
        signing_key,
        agent_id="agent-1",
        verb="read",
        resource="doc/42",
        params={},
        policy_id="rule:read-allow",
        outcome="authorized",
        prev_hash=None,
        issued_at="2026-07-04T00:00:00+00:00",
    )
    print(f"issued:   {env['outcome']} {env['action']['verb']} {env['action']['resource']}")
    print(f"verify:   {'PASS' if verify_envelope(env) else 'FAIL'}")

    env["action"]["resource"] = "doc/secret"  # tamper
    print(f"tampered: {'PASS' if verify_envelope(env) else 'FAIL (as expected)'}")


if __name__ == "__main__":
    main()
