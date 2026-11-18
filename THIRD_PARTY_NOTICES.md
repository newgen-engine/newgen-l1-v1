# Third-party notices for NewGenEngine L1 V1

This publication contains the historical original NewGenEngine source snapshot,
Cargo manifests, the exact main Cargo.lock and license documentation. It does
not distribute crate implementation archives, compiled dependency libraries,
node binaries or operating-system libraries. These notices document external
dependencies and do not relicense their code as proprietary NewGenEngine code.

## Exact dependency scope

All 462 external package/version pairs in the main Cargo.lock were retrieved
from crates.io and their archive SHA-256 values matched the lock. The exact
manifest expressions and a recorded choice for OR alternatives are listed in
DEPENDENCY_LICENSES.csv. The copyright and license texts recovered from those
archives are kept verbatim under third_party/license_texts/. Supplemental
upstream license files are separately identified by repository and commit.

An OR choice records the license route used for this review; it does not remove
the other licenses offered by an upstream author. AND conditions remain
cumulative. Legacy slash-separated declarations are retained verbatim in the
inventory and their selected route is recorded separately.

## Conditions requiring particular care

* attohttpc 0.24.1 is MPL-2.0. Its covered files and any modifications remain
  governed by the MPL. A larger work may use different terms while respecting
  those rights. A later binary distribution must meet the source-availability
  and notice requirements for the MPL-covered component.
* self_cell 1.2.2 offers Apache-2.0 OR GPL-2.0-only; Apache-2.0 is the recorded
  route. r-efi 5.3.0 offers MIT OR Apache-2.0 OR LGPL-2.1-or-later; MIT is the
  recorded route. No GPL/LGPL route is imposed on the original NewGen code by
  those choices.
* ring 0.16.20 has a composite LICENSE, including ISC, OpenSSL/SSLeay and MIT
  material and file-specific notices. Preserve the complete applicable texts,
  copyright notices and acknowledgements. ring 0.17.14 declares Apache-2.0 AND
  ISC and contains additional upstream notices, including once_cell and fiat.
* security-framework 3.6.0 includes a THIRD_PARTY notice for documentation
  adapted from Apple under APSL-2.0. This material must not be described as
  proprietary NewGen documentation or treated as covered only by MIT/Apache.
* unicode-ident 1.0.22 requires Unicode-3.0 in addition to its chosen MIT route.
  Eighteen other packages in this lock declare Unicode-3.0 directly.

Where applicable, retain these upstream acknowledgements from ring 0.16.20:

> This product includes software developed by the OpenSSL Project for use in
> the OpenSSL Toolkit (http://www.openssl.org/)
>
> This product includes cryptographic software written by Eric Young
> (eay@cryptsoft.com)
>
> This product includes software written by Tim Hudson (tjh@cryptsoft.com).

These acknowledgements describe the dependency material and do not imply an
endorsement of NewGenEngine by the named parties.

## Scope limits

The standalone canonical_contracts_rs manifest has version ranges for serde
and serde_json and has no independent Cargo.lock in this snapshot. Its future
standalone resolution is not certified by this 462-package inventory. No new
lock or runtime change has been introduced for this publication.

This notice is for source publication. Before distributing a binary or vendor
tree, identify its actual feature/target dependency closure, preserve the
relevant source notices and satisfy native library requirements, including the
actual OpenSSL version on the target system. No blanket binary-distribution
approval is given by this source-only audit.
