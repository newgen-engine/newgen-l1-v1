# NewGenEngine L1 V1 — validation evidence

This dossier records selected observations from the V1 private testnet. It
contains original API captures, selected fields from a terminal capture, and
the three historical summaries preserved from the earlier publication package.

## Results and their evidence

| Observation | Recorded result | Evidence provided |
|---|---|---|
| Three-node agreement, 8 October 2026 | A/B/C height 328270; finalized height 328269; matching tip and finalized hashes; consensus and quorum ready | Three complete original API JSON files, copied without alteration |
| Restart and subsequent progress, 16 November 2026 | Initial A height 328556; later A/B/C height 328559 and finalized height 328558; matching hashes and readiness true | Complete selected fields and exact fragments from the original truncated terminal capture |
| Earlier three-node observation, 16 November 2026 | Height 328527; finalized height 328526; agreement and quorum reported | Preserved historical summary, not the complete underlying capture |
| Node A offline database verification | At height 328556, integrity OK, issues 0, recovery not required; reopening reported | Preserved historical summary; the complete offline verification transcript is not included |

For the exact hashes, source digests, transformations and evidence classes, see
[EVIDENCE_INDEX.json](EVIDENCE_INDEX.json) and
[EVIDENCE_REPORT.md](EVIDENCE_REPORT.md).

## Inspect the captures

- [8 October capture timestamp](captures/20261008/api_capture_utc.txt)
- [Node A API](captures/20261008/nodeA_status_full.json),
  [Node B API](captures/20261008/nodeB_status_full.json),
  [Node C API](captures/20261008/nodeC_status_full.json)
- [16 November restart observations](captures/20261116/restart_observations.json)
- [Exact selected API field fragments](captures/20261116/restart_api_field_excerpt.txt)

The restart transcript includes an initial state where A has not reached
consensus/quorum readiness. The later three-node state and A's height/finality
advance are recorded separately. Truncated responses have not been completed
or presented as original valid JSON.

## Interpretation

The common chain height exceeds 328000 in the published captures. This is a
reported chain height, not an independent re-execution of every historical
block. The API field `total_blocks` has different values on different nodes;
it must not be substituted for `height` or used as a count of blocks personally
mined by any one node. Transaction counters do not measure throughput.

These results concern the historical private testnet. They do not assert that
every historical run succeeded, establish public-mainnet readiness, or replace
a security review. Known historical qualifications and binary-identity limits
are recorded in [EVIDENCE_REPORT.md](EVIDENCE_REPORT.md).
