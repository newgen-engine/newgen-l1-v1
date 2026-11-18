# V1 evidence report

Publication review: 18 November 2026. No nodes were started, stopped or reset
to produce this dossier. Existing results were inspected and packaged.

## 1. Original October acquisition

The original archive `l1_evidence_20261008_184334_complete.tar.gz` has SHA-256
`cfd433ea8ec026c7cd560c5c0635ec792d410db7f37651dfcb3b42039ae7f039`. All 19 file members were read; all
18 entries in its original manifest matched. The archive itself is not
redistributed because it includes operational material and credentials.

The three published status JSON files are byte-identical to the original
members. Their acquisition timestamp is `2026-10-08T19:56:10+00:00`. All three report:

- Height: **328270**; finalized height: **328269**.
- Tip hash: `ea37c2fa32de1bfba0e5d55f34b2a62edd002412f5ba20232b38a51861aed014`.
- Finalized hash: `2d8031fcea792c0d48a15601a3ac044a6e70aa5bb2234e4aea0f59801fd932b4`.
- Consensus ready and operational quorum ready: **true**.
- Software version 1.0.0, protocol 3, private-testnet network identifier.

The full files retain historical public validator identifiers and API field
names. No launch configuration, password, admin token or private key is
included. The original capture, rather than a rewritten PASS flag, is available
for comparing the three reported views.

### Qualification of this acquisition

Contemporaneous logs in the original archive also record snapshot-export
failures on node A with a backend-height mismatch; B and C record successful
exports. The three positive API captures are not a claim that all October
subsystems were healthy or that every historical test passed. The different
`total_blocks` values in the three APIs are preserved; only their common
`height`, tip and finalized checkpoint are used for the agreement claim.
The original capture does not independently validate each block or its finality
certificate.

## 2. November restart capture

Source: `Testo incollato(20261116-010525).txt`, SHA-256 `1930eff1d771be6e2d0d46726d6e7228164921f989ba2a17e0dee3a095481741`.
The transcript records a session created on 16 November 2026 at 02:04:21;
its timezone and the exact UTC timestamps of the API observations are not
specified. The transcript contains four truncated API lines, each 1800
characters long. Complete visible fields were extracted without inventing
the truncated suffix.

| State | Height | Finalized height | Consensus ready | Quorum ready |
|---|---:|---:|---|---|
| Initial A | 328556 | 328555 | false | false |
| Later A | 328559 | 328558 | true | true |
| Later B | 328559 | 328558 | true | true |
| Later C | 328559 | 328558 | true | true |

Later common tip hash:
`eb1eea6a03896a41f0f7e99232c3684866de847ec900e817bbd1040952298da8`.

Later common finalized hash:
`13d2d89362e9f97e77f298b3cec27653166fe5de4a34f7530ebcf05e578497d5`.

The same transcript therefore shows A advancing by three heights and three
finalized heights, followed by matching ready states on all three nodes.
The public JSON is a derived observation record; the accompanying text contains
exact selected field fragments. Neither is labelled as a complete original API
response. This observation does not prove that every earlier storage issue was
resolved in every scenario.

## 3. Preserved historical summaries

The three original publication-summary JSON files have not been edited.
They retain the recorded H328527 agreement, offline database-verification
result at H328556, and subsequent positive checks. These remain historical
reported results. In particular, the complete offline verifier output is not
included in this dossier; this packaging review did not re-run that verifier.
The visible initial A state in the restart transcript is consistent with a
startup interval and is not replaced by an invented readiness PASS.

## 4. Source and executable identity

| Reference | Digest or status |
|---|---|
| Original reviewed source archive | `c1aa6cabc78788d60a11b40164f1060179c45e54cf4dbef38129f667658664a0` |
| Published main Cargo.lock | `c78fced548970ce8cac6a35ab4cf9070bdc6da37da2446273d7478057085421c` |
| October executable digest recorded by the operator | `693fcb08255e54980031498a600573df199494aef55f5f2f0dd84f9bf62b929a` |
| November reference executable digest in PUBLICATION_CHANGES.json | `52a6fd5fd535376031e25593ff248d25993883b5e50c53dfaafb105beffb9bd9` |
| Reproducible source-to-executable build performed in this review | No |

The October and November executable digests are different. The October
acquisition is evidence of that historical run; it must not be relabelled as
proof of an identical executable built from the published November source.
The publication record supplies source and executable references but does not
replace a reproducible-build procedure. The public source copy contains the
two already-documented test-address anonymizations. This dossier changes no
Rust source, Cargo manifest, Cargo.lock or dependency version.

## 5. Integrity and review limits

`EVIDENCE_INDEX.json` links observations to source digests, original member
digests and line locations. The repository-level `SHA256SUMS.txt` covers the
delivered files. These hashes establish byte identity and consistency; they
are not signatures, trusted timestamps, third-party attestations, or proof of
the truth of every API field. A chain certificate, original database and
runtime environment are not redistributed.

Known dependency notices are documented separately in
[DEPENDENCY_REVIEW.md](../DEPENDENCY_REVIEW.md). Functional observations and
dependency-security findings are both retained with their respective scope.
