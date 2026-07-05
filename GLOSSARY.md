# Glossary

Acronyms used across the agent-evidence stack. **These expansions are canonical —
use them verbatim and identically in every repo.** The source of truth for `ARP` /
`VRP` / `DAT` is [sm-arp](https://github.com/Sharathvc23/sm-arp); for `PARC`,
[sm-parc](https://github.com/Sharathvc23/sm-parc); for `AAE`, this repo.

## Stack terms

| Acronym | Expansion | What it is |
| --- | --- | --- |
| **ARP** | Agency Receipt Protocol | The signed receipt envelope — *what an agent did*. |
| **VRP** | Verifiable Receipts Profile | Composes ARP receipts into a Receipts Ledger + commitment (`behavioral_merkle_root`) + the corroborated `nanda-rep/0.2` scoring (`sm_arp.vrp`). |
| **PARC** | Portable Agent Reputation Credential | A signed W3C Verifiable Credential over a VRP facet, plus the admission gate. |
| **DAT** | Delegated Authority Token | The companion to ARP — *what an agent was allowed to do* (a sketch in ARP v0.1, normative in v0.2). |
| **AAE** | Attested Action Envelope | The signed, per-agent-chained record of a pre-action authorization verdict — *what an agent may do, and the refusals* (this repo). |

## sm-aae terms

| Term | Meaning |
| --- | --- |
| **envelope** | The eight-field signed object. See [`SPEC.md`](SPEC.md) §3. |
| **outcome** | The verdict: `authorized`, `denied`, or `conditional`. |
| **envelope hash** | SHA-256 of the full signed envelope; the value a successor's `prev_hash` points at. |
| **chain** | An agent's envelopes linked genesis-first by `prev_hash`. |
| **gap / fork / foreign-chain splice** | The chain defects `order_chain` rejects. See [`THREATMODEL.md`](THREATMODEL.md). |
