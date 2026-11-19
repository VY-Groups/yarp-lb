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

## Project license scope

The root `LICENSE` applies AGPL-3.0-or-later to the GatewayCore repository as a
whole, including files that previously had no root license declaration. This
is a project-wide licensing change, not a license limited to the NSEC3 file.
The upstream OpenGSLB commercial alternative is not included or granted by
this repository. Review the AGPL obligations before distributing or operating
a modified network service.
