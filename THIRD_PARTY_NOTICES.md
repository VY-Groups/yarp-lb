# Third-party notices

## OpenGSLB NSEC3 hash encoding

GatewayCore's opt-in DNSSEC NSEC3 SHA-1/base32hex hash encoding in
`engines/GslbDns/DnssecZoneSigner.cs` is adapted from the bounded hash
calculation in OpenGSLB, `pkg/dnssec/nsec3.go`.

Copyright 2025 Logan Ross. The original file is marked
`AGPL-3.0-or-later OR LicenseRef-OpenGSLB-Commercial`. This project uses the
AGPL-3.0-or-later option for this adapted material. Only the canonical NSEC3
hash encoding was adapted; OpenGSLB's synthetic denial-proof generation was
not used. GatewayCore creates a complete hash ring from its configured
authoritative names and constructs denial proofs from that ring.

## GatewayCore ownership and licensing transition

The owner intends GatewayCore to become a **proprietary commercial product**.
A customer licensing/activation module and commercial license terms are
**deferred until the remaining software development issues are closed**.
There is no root `LICENSE` file in the current main-branch checkout; prior
repository revisions included an AGPL-3.0-or-later project-wide license.
The absence of that file now does not revoke any valid licenses previously
granted for those revisions.

**Do not infer that the current source tree is already free of AGPL duties.**
The NSEC3 adaptation described above remains attributed to third-party
AGPL-3.0-or-later material. The OpenGSLB commercial alternative has **not**
been established in this repository. Before proprietary distribution or
use of modified network-service code, the owner must obtain appropriate
rights or arrange a legally reviewed clean replacement. Retain provenance
records and license notices; do not delete or relabel upstream attribution
to force a proprietary status.

This file reports the known source provenance; it is not itself a new
customer license or an assertion that all dependencies are cleared.
