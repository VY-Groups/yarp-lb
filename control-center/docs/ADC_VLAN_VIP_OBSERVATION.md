# VLAN and virtual IP observation

Open Infrastructure inventory as an Administrator or Operator. Linux 802.1Q rows come from /proc/net/vlan/config in the current network namespace; missing kernel inventory is not proof of zero VLANs. Windows is explicitly unsupported for VLAN tag discovery. The interface snapshot compares configured virtual socket IPs against actual local interface addresses. A present, up interface is not ownership fencing, a successful bind, reachability, or failover. Duplicate assignment and incomplete snapshots are reported separately. No network changes, shell commands, switch trunk inference or failover automation are performed.

Use this preflight before approved OS network modifications; capture separate peer ownership, routing, ARP/ND convergence and physical acceptance evidence. No new runtime dependencies or internet requirements.
