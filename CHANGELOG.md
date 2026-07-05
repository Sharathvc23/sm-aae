# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-07-04

Initial release.

### Added

- The eight-field Attested Action Envelope: `agent_id`, `action`, `policy_id`,
  `outcome`, `prev_hash`, `issued_at`, `sig`, `pubkey`.
- `issue_envelope` — build and sign a complete envelope; the only mint path.
- `verify_envelope` — structural + Ed25519 signature verification; never raises
  on hostile input.
- `envelope_hash` / `canonical_bytes` — the chain pointer and the exact signed
  bytes.
- `order_chain` — reconstruct an agent's unique causal chain; rejects gaps,
  forks, foreign-chain splices, duplicates, and multiple/zero genesis.
- First-class `denied` verdicts (a refusal is a signed receipt, not an absence).
- `SPEC.md` (normative wire format), `WHITEPAPER.md`, `THREATMODEL.md`.
- Example-based tests, a Hypothesis property battery, 100% line coverage.
