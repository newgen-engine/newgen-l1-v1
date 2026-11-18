# V1 dependency review and maintenance disposition

Reviewed: 18 November 2026. Version matches are those of the recorded OSV query
on the unchanged Cargo.lock. This document adds source inspection and explicit
maintenance dispositions; it does not relabel unresolved notices as fixed.

## Publication decision

Preserve this V1 source baseline and its historical evidence. Keep dependency
notices visible. Evaluate corrections on the implementation intended for
future supported operation, with a separately identified lock and executable.
No supported production-security verdict is issued for this preserved snapshot.

The 34 matched package/version pairs include both security and maintenance
notices. A version match is not an observed NewGen failure or an exploit test.
Historical positive results remain valid within their documented scenarios.

## Configured network components

Cargo.toml pins libp2p to `=0.53.0`, disables default features and explicitly
enables Gossipsub, Yamux, TCP and other listed features. Cargo.lock selects
`libp2p-gossipsub 0.46.1` and `libp2p-yamux 0.45.2`.

In src/p2p.rs, the application instantiates Gossipsub (around lines 9731–9762)
and configures TCP and relay transports with `yamux::Config::default`
(around lines 9804–9812). The wrapper's default selects Yamux 0.13, which is
locked to 0.13.8. Yamux 0.12.1 also exists in the wrapper's dependency set;
its presence is not treated as proof that the application selects it.

### Gossipsub: priority review before untrusted operation

| Notice | Relevant source observation in locked 0.46.1 | Upstream fix lower bound |
|---|---|---|
| [RUSTSEC-2026-0535](https://rustsec.org/advisories/RUSTSEC-2026-0535.html) | backoff.rs stores expiry with unchecked time addition | 0.49.3 |
| [RUSTSEC-2026-0537](https://rustsec.org/advisories/RUSTSEC-2026-0537.html) | backoff.rs heartbeat comparison adds slack without checked arithmetic | 0.49.4 |
| [RUSTSEC-2026-0536](https://rustsec.org/advisories/RUSTSEC-2026-0536.html) | behaviour.rs records GRAFT topics before later topic checks | 0.49.5 |
| [RUSTSEC-2026-0534](https://rustsec.org/advisories/RUSTSEC-2026-0534.html) | PRUNE handling calls mesh-removal/backoff handling before checking whether the topic is in the mesh | 0.50.1 |

The relevant dependency and application configuration are confirmed in source.
The upstream reports concern service interruption through specially crafted
protocol traffic. No attack was run against NewGen, and the exact process-level
impact and current external reachability were not measured.

The application has signed message validation, Hello checks, reputation and
connection limits. This review has not demonstrated that those controls protect
the library control-message paths described by these notices. They therefore
are not counted as proven mitigations. Version 0.50.1 covers the four listed
fix lower bounds only; selecting an upgrade still requires compatibility and
other-advisory review. The current libp2p pin does not permit that Gossipsub
series as a simple unchanged-manifest lock update.

### Yamux: priority review before untrusted operation

- [GHSA-4w32-2493-32g7](https://github.com/advisories/GHSA-4w32-2493-32g7)
  covers malformed flow-control updates in 0.13.0 through versions before
  0.13.9. The selected 0.13.8 falls in that range.
- [GHSA-vxx9-2994-q338](https://github.com/advisories/GHSA-vxx9-2994-q338)
  lists a Data-frame panic fixed in 0.13.10 in the reviewed advisory database.
  The upstream repository's advisory table names 0.13.9 while the reviewed
  database uses the broader range below 0.13.10. That discrepancy is retained,
  not treated as a clean verdict for older versions. The locked 0.13.8 contains
  the stream-removal assertion discussed in the report; the full triggering
  path has not been executed in NewGen.

The two-version wrapper means that updating one lock entry does not by itself
prove all related notices resolved. The 0.13 path is the default in the audited
application. Compatibility and corrected-path verification remain required
for an operational candidate.

## Other networking-related conditions

| Component | What is established | What remains to establish |
|---|---|---|
| bytes 1.10.1 | Networking stacks depend on it; reserve-overflow fix is recorded from 1.11.1 | Whether NewGen can request the affected capacities and which callers can supply them |
| Tokio 1.48.0 | Direct runtime dependency; notice concerns particular Unix AsyncFd constructors | Whether the affected constructor and ownership pattern are used by the actual target build |
| h2 0.3.27 | Warp enables Hyper HTTP/2; upstream empty-frame notice matches the version | Actual HTTP/2 use, endpoint exposure and queue-draining path; upstream fix is on h2 0.4.16 or later, requiring compatibility analysis with Hyper/Warp |
| Hickory 0.24.4 | libp2p DNS feature is enabled and resolver dependencies are locked | Audited SwarmBuilder has no explicit with_dns call; DNS parsing, text-zone parsing and DNSSEC conditions must be assessed individually |
| TLS/webpki | Several versions exist; Warp's TLS feature is enabled | Audited API launch uses plain run(addr), not the TLS builder. Feature availability is not proof of active TLS processing |
| QUIC/Quinn | Versions exist in Cargo.lock | Root libp2p features do not select QUIC. A complete build graph is needed before treating these as operational attack surface |
| ring 0.16.20 | Old version exists via rcgen; separate 0.17.14 also exists | Selected transport path and conditional AES/overflow-check configuration. Do not conflate the two versions |
| bincode 1.3.3 | Unmaintained notice; used in persisted state/storage | Any replacement must preserve or explicitly migrate stored representations. No vulnerability is inferred from the maintenance notice alone |

The source's default API binding is loopback. The P2P listener is configured
for all local interfaces. Those source defaults are not evidence of the current
firewall, routing, live process flags or Internet accessibility. No current
node was contacted or reconfigured. Existing online nodes require their own
operational assessment before being relied on against untrusted peers.

## Disposition and proportionate validation

| Work item | Disposition |
|---|---|
| Preserve source/lock and historical observations | Done in this publication |
| Record exact-version notices and source-level priorities | Done; per-version entries below |
| Establish actual target/feature graph and remaining affected-function paths | Pending for the operational implementation |
| Choose compatible network/runtime corrections or remove unused features | Planned; no update applied to the historical baseline |
| Validate the corrected candidate | Planned: compilation, relevant existing regressions, multi-node connection/propagation/catch-up/finality/restart checks and controlled checks of corrected rejection paths |

A later change that affects persisted encoding, hashing, signatures or consensus
needs the corresponding compatibility checks. A network-only correction does
not automatically justify repeating all unrelated historical test campaigns.
No reset of existing chains, genesis, balances or databases is part of this
publication work.

## Per-version classification

These are initial source-based dispositions, not 34 closed security findings.
No row asserts a reproduced runtime exploit or a fix applied to this snapshot.
Machine-readable details are in [DEPENDENCY_REVIEW.json](DEPENDENCY_REVIEW.json).

| Package/version | Classification | Assessment |
|---|---|---|
| `anyhow 1.0.100` | EXACT_VERSION_MATCH_REQUIRES_PATH_REVIEW | Exact version matches retained; feature, target and affected-function applicability not established by this review. |
| `bincode 1.3.3` | MAINTENANCE_WITH_PERSISTENCE_COMPATIBILITY | Upstream unmaintained notice; storage and state SMT use bincode. Replacement requires data-format compatibility analysis, not an automatic version bump. |
| `bytes 1.10.1` | CORE_RUNTIME_CONDITIONAL_PATH | Buffer dependency used by networking stack; the exact BytesMut reserve overflow path has not been demonstrated in NewGen. |
| `chrono 0.4.42` | MAINTENANCE_REVIEW | Maintenance notice; not itself a demonstrated exploitable vulnerability in the node. |
| `core2 0.4.0` | MAINTENANCE_REVIEW | Maintenance notice; not itself a demonstrated exploitable vulnerability in the node. |
| `crossbeam-epoch 0.9.18` | EXACT_VERSION_MATCH_REQUIRES_PATH_REVIEW | Exact version matches retained; feature, target and affected-function applicability not established by this review. |
| `h2 0.3.27` | HTTP2_CONDITIONAL_PATH | Warp enables Hyper HTTP/2; actual protocol use, endpoint exposure and empty-frame path not tested. |
| `hickory-proto 0.24.4` | DNS_FEATURE_AND_PATH_DEPENDENT | DNS feature enabled in libp2p, but audited SwarmBuilder has no explicit with_dns call; individual parsing/DNSSEC paths are not all established. |
| `hickory-resolver 0.24.4` | DNS_FEATURE_AND_PATH_DEPENDENT | Resolver package associated with enabled libp2p DNS feature; actual resolver/DNSSEC paths not demonstrated. |
| `instant 0.1.13` | MAINTENANCE_REVIEW | Maintenance notice; not itself a demonstrated exploitable vulnerability in the node. |
| `libp2p-gossipsub 0.46.1` | PRIORITY_NETWORK_COMPONENT | Gossipsub instantiated in src/p2p.rs; locked source patterns reviewed; no attack executed. |
| `libp2p-quic 0.10.3` | OPTIONAL_TRANSPORT_NOT_SELECTED_IN_ROOT_MANIFEST | Root libp2p features do not select QUIC; presence in Cargo.lock alone does not establish use. |
| `lru 0.11.1` | EXACT_VERSION_MATCH_REQUIRES_PATH_REVIEW | Exact version matches retained; feature, target and affected-function applicability not established by this review. |
| `lru 0.12.5` | EXACT_VERSION_MATCH_REQUIRES_PATH_REVIEW | Exact version matches retained; feature, target and affected-function applicability not established by this review. |
| `paste 1.0.15` | MAINTENANCE_REVIEW | Maintenance notice; not itself a demonstrated exploitable vulnerability in the node. |
| `pin-utils 0.1.0` | MAINTENANCE_REVIEW | Maintenance notice; not itself a demonstrated exploitable vulnerability in the node. |
| `quinn-proto 0.11.13` | OPTIONAL_TRANSPORT_REQUIRES_BUILD_GRAPH | QUIC dependencies in lock; no QUIC transport selected in audited root manifest; complete target feature graph not reconstructed. |
| `quinn-udp 0.5.14` | OPTIONAL_TRANSPORT_REQUIRES_BUILD_GRAPH | Same optional-transport limitation; no runtime exploitability conclusion. |
| `rand 0.8.5` | EXACT_VERSION_MATCH_REQUIRES_PATH_REVIEW | Exact version matches retained; feature, target and affected-function applicability not established by this review. |
| `rand 0.9.2` | EXACT_VERSION_MATCH_REQUIRES_PATH_REVIEW | Exact version matches retained; feature, target and affected-function applicability not established by this review. |
| `ring 0.16.20` | CRYPTO_VERSION_AND_FEATURE_DEPENDENT | Matched version is 0.16.20 via rcgen; separate ring 0.17.14 is also locked. AES advisory is conditional; actual selected chain and build flags require confirmation. |
| `rustix 1.1.2` | EXACT_VERSION_MATCH_REQUIRES_PATH_REVIEW | Exact version matches retained; feature, target and affected-function applicability not established by this review. |
| `rustls 0.22.4` | TLS_VERSION_AND_CONFIGURATION_DEPENDENT | Warp TLS feature is enabled, but the audited API launch uses plain run(addr); TLS runtime use and other transport paths require confirmation. |
| `rustls 0.23.35` | TLS_VERSION_AND_CONFIGURATION_DEPENDENT | Warp TLS feature is enabled, but the audited API launch uses plain run(addr); TLS runtime use and other transport paths require confirmation. |
| `rustls-pemfile 2.2.0` | MAINTENANCE_REVIEW | Maintenance notice; not itself a demonstrated exploitable vulnerability in the node. |
| `rustls-webpki 0.101.7` | TLS_VERSION_AND_CONFIGURATION_DEPENDENT | Several certificate-validation versions are locked; the actual active TLS paths and individual advisory conditions have not been demonstrated. |
| `rustls-webpki 0.102.8` | TLS_VERSION_AND_CONFIGURATION_DEPENDENT | Several certificate-validation versions are locked; the actual active TLS paths and individual advisory conditions have not been demonstrated. |
| `rustls-webpki 0.103.8` | TLS_VERSION_AND_CONFIGURATION_DEPENDENT | Several certificate-validation versions are locked; the actual active TLS paths and individual advisory conditions have not been demonstrated. |
| `time 0.3.44` | EXACT_VERSION_MATCH_REQUIRES_PATH_REVIEW | Exact version matches retained; feature, target and affected-function applicability not established by this review. |
| `tokio 1.48.0` | CORE_RUNTIME_CONDITIONAL_PATH | Direct runtime dependency; advisory concerns specific Unix AsyncFd constructors, not every Tokio operation. |
| `xxhash-rust 0.8.15` | EXACT_VERSION_MATCH_REQUIRES_PATH_REVIEW | Exact version matches retained; feature, target and affected-function applicability not established by this review. |
| `yaml-rust 0.4.5` | MAINTENANCE_REVIEW | Maintenance notice; not itself a demonstrated exploitable vulnerability in the node. |
| `yamux 0.12.1` | PRIORITY_NETWORK_COMPONENT | TCP and relay use yamux::Config::default; wrapper selects the 0.13 implementation. The 0.12 version remains a legacy dependency, not the selected default. |
| `yamux 0.13.8` | PRIORITY_NETWORK_COMPONENT | TCP and relay use yamux::Config::default; wrapper selects the 0.13 implementation. The 0.12 version remains a legacy dependency, not the selected default. |


## Primary references and scope

The complete matched-ID list is retained in DEPENDENCY_SECURITY_NOTICES.md.
Additional upstream records consulted for the conditions above:

- https://rustsec.org/advisories/RUSTSEC-2026-0007.html
- https://rustsec.org/advisories/RUSTSEC-2026-0386.html
- https://rustsec.org/advisories/RUSTSEC-2026-0258.html
- https://rustsec.org/advisories/RUSTSEC-2026-0491.html
- https://rustsec.org/advisories/RUSTSEC-2025-0009.html
- https://rustsec.org/advisories/RUSTSEC-2025-0141.html
- https://github.com/libp2p/rust-yamux/security/advisories/GHSA-vxx9-2994-q338
- https://doc.rust-lang.org/cargo/commands/cargo-update.html

Application and library-source inspection was static. It is distinct from
compilation, native cargo-audit, a resolved target feature graph, penetration
testing and a live-node assessment. Upstream version ranges are reference
information, not an approved NewGen upgrade recipe.
