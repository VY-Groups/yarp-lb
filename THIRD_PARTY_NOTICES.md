# Reference projects and historical license records

## OpenGSLB — technical reference only (owner clarification, 2026-11-21)

The owner confirms that OpenGSLB was examined to understand DNS/GSLB
architecture and expected functionality. GatewayCore's opt-in NSEC3 logic in
`engines/GslbDns/DnssecZoneSigner.cs` is a separate C# implementation of
the RFC 5155 algorithm; no OpenGSLB Go package is linked. A comparison of
the OpenGSLB Go function and the GatewayCore C# implementation shows
different language/framework structures implementing the same public
DNSSEC standard. That comparison alone cannot resolve the origin of every
historical source annotation.

The existing C# source has historically carried a file-level
`AGPL-3.0-or-later` SPDX marker and referenced the OpenGSLB source file
`pkg/dnssec/nsec3.go`. OpenGSLB's source records
**Copyright 2025 Logan Ross** and
`AGPL-3.0-or-later OR LicenseRef-OpenGSLB-Commercial`.
These details are retained as **historical provenance records pending
independent review**, not as a confirmed conclusion that third-party
implementation code was used. An owner statement of reference-only use also
does not, by itself, settle the legal status of legacy marks. Preserve
the original repository history and source notices until a review confirms
what licensing, if any, applies to the current implementation.

GatewayCore's denial-proof generation builds its own authoritative-name
hash ring and RFC 5155 closest-encloser, next-closer, wildcard and exact-owner
proofs. This file is a reference/provenance ledger, not a new software
license, assignment or third-party endorsement.

## GatewayCore ownership and future licensing

GatewayCore is intended to be an **owner-controlled proprietary software
product**, not an open-source product offering. The customer license,
activation and pricing module is deferred until outstanding software
development issues are complete.

The current checkout has no root `LICENSE` file. Earlier revisions included
a project-wide AGPL text and an interpretation of the NSEC3 source's
provenance that the owner has now disputed. Preserve the history; do not
claim either that prior grants can be revoked simply by editing a README
or that the present code necessarily carries the reference project's license.
A proper provenance/legal review is required before issuing definitive
closed-source distribution and network-service licensing claims.
