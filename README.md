# NewGenEngine L1 V1 — source and validation evidence

NewGenEngine L1 V1 is a Rust blockchain implementation. This repository
publishes its preserved source baseline together with documented observations
from the V1 private testnet, for technical inspection under the proprietary
terms of [LICENSE.txt](LICENSE.txt).

## Documented results

The published captures show three nodes agreeing above chain height 328000,
with matching tip and finalized checkpoint hashes. A later capture also shows
progress after a full three-node restart.

| Observation | Recorded result | Supporting material |
|---|---|---|
| 8 October 2026, three nodes | H328270; finalized H328269; identical hashes; consensus and quorum ready | Three complete original API captures |
| 16 November 2026, after restart | Initial A H328556; later A/B/C H328559 and finalized H328558; identical hashes and readiness true | Selected complete fields from the original terminal capture, with exact field excerpts |
| Node A offline database check | At H328556, integrity OK; issues 0; recovery not required; reopening reported | Preserved historical result summary; full verifier transcript is not included |

Start with the [evidence dossier](evidence/README.md), its
[report](evidence/EVIDENCE_REPORT.md) and
[source index](evidence/EVIDENCE_INDEX.json). Evidence types, dates, hashes and
transformations are identified explicitly. These are observations of the
private testnet, not an independent re-execution of every historical block.

## Status and security

This repository preserves the V1 baseline used for historical documentation.
The source and locked dependencies have not been upgraded in this publication.
Known upstream security and maintenance notices are disclosed in
[DEPENDENCY_SECURITY_NOTICES.md](DEPENDENCY_SECURITY_NOTICES.md).

The [dependency review](DEPENDENCY_REVIEW.md) identifies configured networking
components, confirms relevant source patterns, and records the remaining
applicability and maintenance work. The preserved dependency set is not offered
as a supported production release. Functional test results and dependency
security findings have separate scopes; both are documented.

For security reporting and deployment scope, see [SECURITY.md](SECURITY.md).

## Source provenance

The original reviewed source archive has SHA-256
`c1aa6cabc78788d60a11b40164f1060179c45e54cf4dbef38129f667658664a0`.
The public source files differ only in the two previously documented test files
whose historical IPv4 literals were replaced with RFC 5737 example addresses.
See [PUBLICATION_CHANGES.json](PUBLICATION_CHANGES.json) for the source and
executable references. The October and November executable digests differ;
the evidence report does not equate them or claim a reproducible build.

The 18 November documentation closure changes no Rust source, Cargo manifest,
lock file or dependency version. Integrity digests are in
[SHA256SUMS.txt](SHA256SUMS.txt).

## Licensing and permitted inspection

Copyright (c) 2026 Danilo Bringheli. Original NewGenEngine material is made
available for reading and technical source inspection under
[LICENSE.txt](LICENSE.txt). Broader execution, modification, integration or
redistribution rights require separate written permission, subject to the
platform rights and mandatory legal exceptions stated in that license.

Third-party components retain their own licenses. The exact-version inventory
and notices are in [DEPENDENCY_LICENSES.csv](DEPENDENCY_LICENSES.csv) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Build information for separately authorized users

The manifest declares Rust 1.90 as the minimum version. The recorded build
command for the main binary is:

```bash
cargo build --release --locked --bin newgen_engine
```

Compilation and tests of this public copy have not been independently
reproduced in this publication review. The build information does not grant
additional rights beyond LICENSE.txt. Runtime configuration, genesis,
keystores, chain databases and snapshots are not supplied.

## Publication scope and contact

This repository contains the L1 V1 baseline and its selected evidence. L1
V2/S5, the operational E2 Compute Hub and NewGen AI implementations remain
outside this publication. L1 interface contracts that refer to E2/AI are
historical L1 source interfaces, not those other implementations.

Technical inspection, licensing and security enquiries:
newgenengine.official@gmail.com.
