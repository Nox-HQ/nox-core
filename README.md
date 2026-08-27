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
| `evidence` | the exploitability lifecycle, evidence kinds and their strengths, confidence aggregation |
| `vulnsource` | the vulnerability-source seam and the OSV-compatible wire format, including NOX's superset extensions |
| `degrade` | the vocabulary for "this check could not complete" |

`evidence` is the reason this module exists. One definition of CONFIRMED, in one
place, is the only way the scanner and the service cannot drift apart about what
the word means. A duplicated copy would let one side re-weight the evidence
ladder while the other did not, and nothing would fail — which is precisely the
failure the spine was written to prevent.

`vulnsource` is shared for a narrower reason: most of it is the public OSV
schema, which anyone may implement independently, but `Record.Intelligence`
(`nox_intelligence` on the wire) and the candidate identifiers are NOX's own
superset extensions. Two definitions of those would stop round-tripping without
saying so.

## Stability

Both consumers pin a released version. Changes here are breaking changes for
two repositories at once, which is the intended friction: a shared kernel that
is cheap to change is a shared kernel that drifts.
