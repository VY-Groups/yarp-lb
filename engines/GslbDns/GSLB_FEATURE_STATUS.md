# GatewayCore GSLB feature status

This document tracks GatewayCore behavior and remaining GSLB acceptance work. Feature targets are defined by the product requirements and relevant DNS standards.

| Capability | GatewayCore status |
| --- | --- |
| Authoritative A/AAAA records over UDP and TCP | Implemented; integration coverage continues |
| Health-aware and weighted answers | Implemented with configurable health thresholds |
| Ordered failover behavior | Implemented; production acceptance remains open |
| DNSSEC NSEC3 signing | Implemented against RFC 5155; key lifecycle and parent DS coordination remain open |
| GeoIP and ASN routing | Not implemented; requires a selected and properly licensed data source |
| EDNS Client Subnet | Partial; trusted resolver configuration and privacy acceptance remain open |
| Authenticated distributed health and partition fencing | Partial; adversarial multi-node acceptance remains open |
| Management API and UI integration | Partial; runtime policy operations remain open |
| Live delegation, scale, split-brain and physical DC/DR acceptance | Open; tracked under issues #52, #109 and #36 |

CI and local integration tests establish only the behavior they exercise. They do not certify public DNS operation, customer infrastructure, or production availability.
