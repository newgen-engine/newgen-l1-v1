# Security policy

## Supported scope

This repository preserves NewGenEngine L1 V1 for source inspection and
historical documentation under LICENSE.txt. It is not a supported production
release. No deployment rights or operational configuration are supplied.

Historical private-testnet results are documented in evidence/. They establish
specific observed behavior and are retained alongside, rather than replaced
by, the dependency-security review.

## Known dependency notices and disposition

The unchanged Cargo.lock contains 462 external package/version pairs. The
recorded 18 November 2026 OSV query matched notices for 34 pairs. Both security
and maintenance notices are included; the count is not a number of demonstrated
exploits against NewGen. See DEPENDENCY_SECURITY_NOTICES.md.

DEPENDENCY_REVIEW.md identifies configured networking components and confirmed
source patterns. Gossipsub and the default Yamux implementation require priority
assessment before untrusted operation. The source review does not establish
current Internet exposure or a runtime exploit. No dependency fix is claimed
for this preserved snapshot. Future supported operation requires a separately
reviewed and validated maintenance candidate.

Optional, development and platform-specific dependencies must be distinguished
from the actual target build; an untested path is not labelled safe or unreachable.
Publication-content and licensing checks are not a production-security audit.

## Reporting

Send security reports to newgenengine.official@gmail.com. Include the affected
file/version and a concise description. Keep credentials, private keys, personal
data and live operational endpoints out of public issues. Do not test suspected
attacks against live infrastructure without separate authorization.
