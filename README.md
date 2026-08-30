# nox-core

The shared kernel of the NOX security tooling: the evidence spine, the
vulnerability-source seam, and the degradation vocabulary.

It exists so that `nox` (the open-source scanner) and `nox-intelligence` (the
hosted service) can share these definitions **without depending on each other**.
Before this module, the service imported the scanner through a local
`replace` directive, which made the two impossible to build or release apart.

## What is here, and why it is shared rather than duplicated

| package | contents |
|---|---|
| `evidence` | the proposition model: typed subjects and the relations between them, evidence kinds and their strengths, supporting and refuting claims, claim lifecycle, producer authority, the exploitability lifecycle, and confidence aggregation |
| `vulnsource` | the vulnerability-source seam and the OSV-compatible wire format, including NOX's superset extensions |
| `degrade` | the vocabulary for "this check could not complete" |

`evidence` is the reason this module exists. One definition of CONFIRMED, in one
place, is the only way the scanner and the service cannot drift apart about what
the word means. A duplicated copy would let one side re-weight the evidence
ladder while the other did not, and nothing would fail — which is precisely the
failure the spine was written to prevent.

### What a claim is about (v0.2.0)

Until v0.2.0 a `Ledger` was a bag of claims and `Strongest()` picked the
heaviest one in it. That is sound only while every claim concerns the same
proposition, and in practice it does not:

```
OSV advisory: package X is vulnerable            (public_advisory, 100)
static analysis: the affected path is unreachable here
                          ↓
              Strongest() = the advisory
                          ↓
                 "therefore exploitable"
```

Two true statements about two different things, aggregated into one false
conclusion. `Subject` makes that impossible rather than merely discouraged, and
`Relation` gives the six edges that express the chain an applicability argument
actually walks — package *contains* symbol, build *uses* it, a call path
*reaches* it, the flow *originates* at an untrusted input, no control *guards*
it, so a hypothesis *concerns* it.

Three further rules are enforced in the model rather than left to callers:

- **A refutation is a claim, not a deletion.** `Polarity` records evidence
  against a proposition. A missing supporting claim is not a refutation, and
  neither is an analysis that ran and could not answer — that is
  `PolarityUnknown`, and it weighs nothing in either direction.
- **Evidence is not immortal.** `Status` records superseded, retracted,
  invalidated and replaced claims. They stay in the ledger and weigh nothing:
  "we were wrong" must not become "we never said it".
- **Producers do not rank themselves.** `Authority` is an allowlist of which
  evidence kinds a source may assert, so a lexical analyzer cannot emit a
  dynamic-exploit claim and have it weigh like one. Unauthorized claims are
  retained and visible; they simply carry no weight.

Every zero value is the pre-v0.2.0 reading — the unattributed subject, a
supporting claim, an active one, and a non-enforcing authority — so a ledger
written against v0.1.x aggregates to exactly what it did before. That
compatibility is pinned by a test, not promised in a changelog.

Composition **across** subjects is deliberately absent. A package being
affected and a call path being unreachable are both true and neither outranks
the other; turning them into one verdict requires knowing what is being
decided, and that judgement belongs to the consumer.

`vulnsource` is shared for a narrower reason: most of it is the public OSV
schema, which anyone may implement independently, but `Record.Intelligence`
(`nox_intelligence` on the wire) and the candidate identifiers are NOX's own
superset extensions. Two definitions of those would stop round-tripping without
saying so.

## Stability

Both consumers pin a released version. Changes here are breaking changes for
two repositories at once, which is the intended friction: a shared kernel that
is cheap to change is a shared kernel that drifts.

## Licence

Apache 2.0, the same as `nox`, from which this code was extracted. The licence
is not incidental: `nox` is a public Apache-2.0 module that depends on this one,
so a shared kernel under any more restrictive terms — or under none, which is
what an unlicensed public repository means — would leave everyone redistributing
the scanner without the rights to do so.

## Provenance

Extracted from `nox-hq/nox` at commit `703b105` on main, not from the `v1.30.1`
tag: `vulnsource`'s superset model (`status.go`, `verify.go`, `match.go`) landed
after that release. `evidence` and `degrade` are unchanged since `v1.30.1`.
