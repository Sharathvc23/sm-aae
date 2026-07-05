# The Attested Action Envelope

**Signing what an agent may do — refusals included — before it acts.**

## The gap

Agent accountability is almost entirely retrospective. Reputation systems score
past behavior; receipt logs record completed actions; transparency logs anchor
what already happened. All of it answers *what did the agent do?* — and answers
it after the fact.

That leaves a specific blind spot: the moment **before** an action, where a
decision is made about whether the agent may proceed. Two things about that
moment are worth capturing and almost never are:

1. **The decision itself is evidence.** "This action was evaluated against this
   policy and authorized" is a claim an auditor may later need to check — not
   reconstruct from side effects.
2. **A refusal is evidence too, and it usually vanishes.** When a system declines
   an action, it typically just... doesn't do it. There is no signed artifact
   that says "we were asked, and we said no, here, then." A denial is a silent
   absence, indistinguishable later from "never asked."

A well-behaved agent with a long clean record is exactly the case where this
bites: on the one request that should be refused, a good reputation is no help,
because reputation is measured after actions, not before them.

## The envelope

An Attested Action Envelope is a small signed object issued *before* an action
runs. Eight fields: the agent, the action (`verb`/`resource`/`params`), the
policy that decided, the verdict (`authorized` / `denied` / `conditional`), a
link to the agent's previous envelope, a timestamp, and an Ed25519 signature over
the canonical form.

Two design choices carry the weight.

**Denials are first-class.** A `denied` verdict produces a fully signed envelope,
identical in shape to a grant. The refusal becomes a durable, verifiable receipt.
"We said no" is now provable, and an audit can count and inspect refusals the
same way it inspects grants.

**Each agent's envelopes chain by hash.** Every envelope's `prev_hash` is the
SHA-256 of the agent's previous envelope — including that envelope's signature.
An agent's authorization history is therefore a tamper-evident sequence: reorder
it, delete an interior decision, or splice in an envelope from another agent's
chain, and the chain fails to reconstruct. An agent cannot quietly drop the one
decision it would rather not have on record.

## Why minimal

The envelope carries eight fields and nothing else. Richer schemes can layer more
on top — structured policy citations, multiple signers, batching — but the value
of a *primitive* is that it is small enough to implement identically twice and
verify without trusting the issuer's runtime. sm-aae is stdlib plus one crypto
dependency; a second implementation of the eight-field format and its
canonicalization can verify sm-aae's envelopes, and vice versa. That mutual
checkability is the point of a shared primitive.

## Where it sits

Static agent facts say what an agent *is*. Receipts say what an agent *did*. The
envelope says what an agent *may do*, and preserves the refusals. Together they
give a system three tenses of accountable evidence — capability, decision, and
history — each independently verifiable, none requiring trust in the party that
produced it.

## Non-goals

The envelope does not define how policies are written or evaluated; that is the
caller's domain, and `policy_id` is deliberately an opaque identifier. It does not
issue identities or distribute keys. It does not bind an agent to a fixed key
across its history — chain integrity is by hash commitment, not key pinning (see
[`THREATMODEL.md`](THREATMODEL.md)). It is a record format and its verifier,
nothing more — which is exactly what makes it reusable.

---

Built at [labs.stellarminds.ai](https://labs.stellarminds.ai).
