# Dependency security and maintenance notices

Checked on 18 November 2026 against OSV using the exact package versions in
Cargo.lock. This snapshot contains 462 external package/version pairs. The
query returned matches for 34 pairs and 79 advisory records. Deduplicating
explicit aliases yields 59 groups: 50 concern security or soundness and nine
concern maintenance. These are database matches, not 59 demonstrated
vulnerabilities in a deployed NewGenEngine binary.

The lock contains development, optional and platform-specific packages. The
selected build feature graph, actual binary contents, runtime reachability and
application mitigations have not been established by this version query.
No crate was upgraded or runtime logic changed to hide or resolve these
historical notices. The source snapshot is not recommended for production use.

Examples of matched upstream notices include libp2p-gossipsub denial-of-service
reports, yamux panic reports and the conditional ring AES panic advisory.
Refer to each upstream record for its conditions and fixed versions.

| Package | Locked version | Advisory records returned |
|---|---|---|
| `anyhow` | `1.0.100` | [RUSTSEC-2026-0190](https://osv.dev/vulnerability/RUSTSEC-2026-0190) |
| `bincode` | `1.3.3` | [RUSTSEC-2025-0141](https://osv.dev/vulnerability/RUSTSEC-2025-0141) |
| `bytes` | `1.10.1` | [GHSA-434x-w66g-qw3r](https://osv.dev/vulnerability/GHSA-434x-w66g-qw3r); [RUSTSEC-2026-0007](https://osv.dev/vulnerability/RUSTSEC-2026-0007) |
| `chrono` | `0.4.42` | [RUSTSEC-2026-0543](https://osv.dev/vulnerability/RUSTSEC-2026-0543) |
| `core2` | `0.4.0` | [RUSTSEC-2026-0105](https://osv.dev/vulnerability/RUSTSEC-2026-0105) |
| `crossbeam-epoch` | `0.9.18` | [RUSTSEC-2026-0204](https://osv.dev/vulnerability/RUSTSEC-2026-0204) |
| `h2` | `0.3.27` | [RUSTSEC-2026-0258](https://osv.dev/vulnerability/RUSTSEC-2026-0258) |
| `hickory-proto` | `0.24.4` | [GHSA-q2qq-hmj6-3wpp](https://osv.dev/vulnerability/GHSA-q2qq-hmj6-3wpp); [RUSTSEC-2026-0119](https://osv.dev/vulnerability/RUSTSEC-2026-0119); [RUSTSEC-2026-0487](https://osv.dev/vulnerability/RUSTSEC-2026-0487); [RUSTSEC-2026-0489](https://osv.dev/vulnerability/RUSTSEC-2026-0489); [RUSTSEC-2026-0490](https://osv.dev/vulnerability/RUSTSEC-2026-0490); [RUSTSEC-2026-0491](https://osv.dev/vulnerability/RUSTSEC-2026-0491); [RUSTSEC-2026-0505](https://osv.dev/vulnerability/RUSTSEC-2026-0505); [RUSTSEC-2026-0511](https://osv.dev/vulnerability/RUSTSEC-2026-0511); [RUSTSEC-2026-0512](https://osv.dev/vulnerability/RUSTSEC-2026-0512); [RUSTSEC-2026-0530](https://osv.dev/vulnerability/RUSTSEC-2026-0530); [RUSTSEC-2026-0531](https://osv.dev/vulnerability/RUSTSEC-2026-0531); [RUSTSEC-2026-0550](https://osv.dev/vulnerability/RUSTSEC-2026-0550); [RUSTSEC-2026-0551](https://osv.dev/vulnerability/RUSTSEC-2026-0551) |
| `hickory-resolver` | `0.24.4` | [GHSA-5j98-2g5x-46v6](https://osv.dev/vulnerability/GHSA-5j98-2g5x-46v6); [RUSTSEC-2026-0514](https://osv.dev/vulnerability/RUSTSEC-2026-0514) |
| `instant` | `0.1.13` | [RUSTSEC-2024-0384](https://osv.dev/vulnerability/RUSTSEC-2024-0384) |
| `libp2p-gossipsub` | `0.46.1` | [GHSA-gc42-3jg7-rxr2](https://osv.dev/vulnerability/GHSA-gc42-3jg7-rxr2); [GHSA-xqmp-fxgv-xvq5](https://osv.dev/vulnerability/GHSA-xqmp-fxgv-xvq5); [RUSTSEC-2026-0534](https://osv.dev/vulnerability/RUSTSEC-2026-0534); [RUSTSEC-2026-0535](https://osv.dev/vulnerability/RUSTSEC-2026-0535); [RUSTSEC-2026-0536](https://osv.dev/vulnerability/RUSTSEC-2026-0536); [RUSTSEC-2026-0537](https://osv.dev/vulnerability/RUSTSEC-2026-0537) |
| `libp2p-quic` | `0.10.3` | [GHSA-5hq8-qhww-jm7q](https://osv.dev/vulnerability/GHSA-5hq8-qhww-jm7q); [RUSTSEC-2026-0525](https://osv.dev/vulnerability/RUSTSEC-2026-0525) |
| `lru` | `0.11.1` | [GHSA-rhfx-m35p-ff5j](https://osv.dev/vulnerability/GHSA-rhfx-m35p-ff5j); [RUSTSEC-2026-0002](https://osv.dev/vulnerability/RUSTSEC-2026-0002); [RUSTSEC-2026-0253](https://osv.dev/vulnerability/RUSTSEC-2026-0253) |
| `lru` | `0.12.5` | [GHSA-rhfx-m35p-ff5j](https://osv.dev/vulnerability/GHSA-rhfx-m35p-ff5j); [RUSTSEC-2026-0002](https://osv.dev/vulnerability/RUSTSEC-2026-0002); [RUSTSEC-2026-0253](https://osv.dev/vulnerability/RUSTSEC-2026-0253) |
| `paste` | `1.0.15` | [RUSTSEC-2024-0436](https://osv.dev/vulnerability/RUSTSEC-2024-0436) |
| `pin-utils` | `0.1.0` | [RUSTSEC-2026-0441](https://osv.dev/vulnerability/RUSTSEC-2026-0441) |
| `quinn-proto` | `0.11.13` | [GHSA-4w2j-m93h-cj5j](https://osv.dev/vulnerability/GHSA-4w2j-m93h-cj5j); [GHSA-6xvm-j4wr-6v98](https://osv.dev/vulnerability/GHSA-6xvm-j4wr-6v98); [RUSTSEC-2026-0037](https://osv.dev/vulnerability/RUSTSEC-2026-0037); [RUSTSEC-2026-0185](https://osv.dev/vulnerability/RUSTSEC-2026-0185); [RUSTSEC-2026-0338](https://osv.dev/vulnerability/RUSTSEC-2026-0338); [RUSTSEC-2026-0339](https://osv.dev/vulnerability/RUSTSEC-2026-0339); [RUSTSEC-2026-0340](https://osv.dev/vulnerability/RUSTSEC-2026-0340); [RUSTSEC-2026-0342](https://osv.dev/vulnerability/RUSTSEC-2026-0342); [RUSTSEC-2026-0523](https://osv.dev/vulnerability/RUSTSEC-2026-0523); [RUSTSEC-2026-0524](https://osv.dev/vulnerability/RUSTSEC-2026-0524) |
| `quinn-udp` | `0.5.14` | [RUSTSEC-2026-0538](https://osv.dev/vulnerability/RUSTSEC-2026-0538) |
| `rand` | `0.8.5` | [GHSA-cq8v-f236-94qc](https://osv.dev/vulnerability/GHSA-cq8v-f236-94qc); [RUSTSEC-2026-0097](https://osv.dev/vulnerability/RUSTSEC-2026-0097) |
| `rand` | `0.9.2` | [GHSA-cq8v-f236-94qc](https://osv.dev/vulnerability/GHSA-cq8v-f236-94qc); [RUSTSEC-2026-0097](https://osv.dev/vulnerability/RUSTSEC-2026-0097) |
| `ring` | `0.16.20` | [GHSA-4p46-pwfr-66x6](https://osv.dev/vulnerability/GHSA-4p46-pwfr-66x6); [RUSTSEC-2025-0009](https://osv.dev/vulnerability/RUSTSEC-2025-0009); [RUSTSEC-2025-0010](https://osv.dev/vulnerability/RUSTSEC-2025-0010) |
| `rustix` | `1.1.2` | [RUSTSEC-2026-0486](https://osv.dev/vulnerability/RUSTSEC-2026-0486) |
| `rustls` | `0.22.4` | [GHSA-c8m5-c952-6cm4](https://osv.dev/vulnerability/GHSA-c8m5-c952-6cm4); [GHSA-h2v8-394m-p7vv](https://osv.dev/vulnerability/GHSA-h2v8-394m-p7vv); [GHSA-w44r-93j7-qv28](https://osv.dev/vulnerability/GHSA-w44r-93j7-qv28); [RUSTSEC-2026-0346](https://osv.dev/vulnerability/RUSTSEC-2026-0346); [RUSTSEC-2026-0349](https://osv.dev/vulnerability/RUSTSEC-2026-0349) |
| `rustls` | `0.23.35` | [GHSA-2mjx-qc3c-rqvc](https://osv.dev/vulnerability/GHSA-2mjx-qc3c-rqvc); [GHSA-c8m5-c952-6cm4](https://osv.dev/vulnerability/GHSA-c8m5-c952-6cm4); [GHSA-h2v8-394m-p7vv](https://osv.dev/vulnerability/GHSA-h2v8-394m-p7vv); [GHSA-w44r-93j7-qv28](https://osv.dev/vulnerability/GHSA-w44r-93j7-qv28); [RUSTSEC-2026-0285](https://osv.dev/vulnerability/RUSTSEC-2026-0285); [RUSTSEC-2026-0346](https://osv.dev/vulnerability/RUSTSEC-2026-0346); [RUSTSEC-2026-0348](https://osv.dev/vulnerability/RUSTSEC-2026-0348); [RUSTSEC-2026-0349](https://osv.dev/vulnerability/RUSTSEC-2026-0349) |
| `rustls-pemfile` | `2.2.0` | [RUSTSEC-2025-0134](https://osv.dev/vulnerability/RUSTSEC-2025-0134) |
| `rustls-webpki` | `0.101.7` | [GHSA-82j2-j2ch-gfr8](https://osv.dev/vulnerability/GHSA-82j2-j2ch-gfr8); [GHSA-965h-392x-2mh5](https://osv.dev/vulnerability/GHSA-965h-392x-2mh5); [GHSA-xgp8-3hg3-c2mh](https://osv.dev/vulnerability/GHSA-xgp8-3hg3-c2mh); [RUSTSEC-2026-0098](https://osv.dev/vulnerability/RUSTSEC-2026-0098); [RUSTSEC-2026-0099](https://osv.dev/vulnerability/RUSTSEC-2026-0099); [RUSTSEC-2026-0104](https://osv.dev/vulnerability/RUSTSEC-2026-0104); [RUSTSEC-2026-0382](https://osv.dev/vulnerability/RUSTSEC-2026-0382) |
| `rustls-webpki` | `0.102.8` | [GHSA-82j2-j2ch-gfr8](https://osv.dev/vulnerability/GHSA-82j2-j2ch-gfr8); [GHSA-965h-392x-2mh5](https://osv.dev/vulnerability/GHSA-965h-392x-2mh5); [GHSA-pwjx-qhcg-rvj4](https://osv.dev/vulnerability/GHSA-pwjx-qhcg-rvj4); [GHSA-xgp8-3hg3-c2mh](https://osv.dev/vulnerability/GHSA-xgp8-3hg3-c2mh); [RUSTSEC-2026-0049](https://osv.dev/vulnerability/RUSTSEC-2026-0049); [RUSTSEC-2026-0098](https://osv.dev/vulnerability/RUSTSEC-2026-0098); [RUSTSEC-2026-0099](https://osv.dev/vulnerability/RUSTSEC-2026-0099); [RUSTSEC-2026-0104](https://osv.dev/vulnerability/RUSTSEC-2026-0104); [RUSTSEC-2026-0382](https://osv.dev/vulnerability/RUSTSEC-2026-0382) |
| `rustls-webpki` | `0.103.8` | [GHSA-82j2-j2ch-gfr8](https://osv.dev/vulnerability/GHSA-82j2-j2ch-gfr8); [GHSA-965h-392x-2mh5](https://osv.dev/vulnerability/GHSA-965h-392x-2mh5); [GHSA-pwjx-qhcg-rvj4](https://osv.dev/vulnerability/GHSA-pwjx-qhcg-rvj4); [GHSA-xgp8-3hg3-c2mh](https://osv.dev/vulnerability/GHSA-xgp8-3hg3-c2mh); [RUSTSEC-2026-0049](https://osv.dev/vulnerability/RUSTSEC-2026-0049); [RUSTSEC-2026-0098](https://osv.dev/vulnerability/RUSTSEC-2026-0098); [RUSTSEC-2026-0099](https://osv.dev/vulnerability/RUSTSEC-2026-0099); [RUSTSEC-2026-0104](https://osv.dev/vulnerability/RUSTSEC-2026-0104); [RUSTSEC-2026-0382](https://osv.dev/vulnerability/RUSTSEC-2026-0382) |
| `time` | `0.3.44` | [GHSA-r6v5-fh4h-64xc](https://osv.dev/vulnerability/GHSA-r6v5-fh4h-64xc); [RUSTSEC-2026-0009](https://osv.dev/vulnerability/RUSTSEC-2026-0009) |
| `tokio` | `1.48.0` | [RUSTSEC-2026-0386](https://osv.dev/vulnerability/RUSTSEC-2026-0386) |
| `xxhash-rust` | `0.8.15` | [GHSA-6g2r-675j-hx59](https://osv.dev/vulnerability/GHSA-6g2r-675j-hx59) |
| `yaml-rust` | `0.4.5` | [RUSTSEC-2024-0320](https://osv.dev/vulnerability/RUSTSEC-2024-0320) |
| `yamux` | `0.12.1` | [GHSA-vxx9-2994-q338](https://osv.dev/vulnerability/GHSA-vxx9-2994-q338) |
| `yamux` | `0.13.8` | [GHSA-4w32-2493-32g7](https://osv.dev/vulnerability/GHSA-4w32-2493-32g7); [GHSA-vxx9-2994-q338](https://osv.dev/vulnerability/GHSA-vxx9-2994-q338) |

## Application-level review

The additional source review and per-version maintenance dispositions are in
[DEPENDENCY_REVIEW.md](DEPENDENCY_REVIEW.md). They identify configured network
components without claiming that all version matches are exploitable or fixed.

## Method and scope

Queries used https://api.osv.dev/v1/querybatch and retrieved individual records
from the same service. OSV documents its version-query and pagination behavior
at https://google.github.io/osv.dev/post-v1-querybatch/ . The original query
results and alias grouping were retained in the private publication audit.
Version matching is not a native cargo-audit run, a reachability analysis,
a penetration test or a consensus-security certification.
