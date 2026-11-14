# Version 0.1 Redis prototype: disposable GitHub Actions only

This test creates TLS-only Redis master, replica and three TLS Sentinels on one GitHub runner. It tests authentication denial, a read-only ACL, an atomic compare-and-set config revision, replication, primary SIGKILL and Sentinel promotion.

The Redis cluster is **NOT wired into the shipping YARP/Control Center**. Its data structure is a prototype, not a proof of distributed lease or split-brain safety. No network partitions across physical fault domains, CA signing side effects, Redis data-plane coupling or production authorization are claimed.

The three Sentinels are independent containers on **one host**; this does NOT meet P0 #36. Passwords, CAs and certificates are generated and destroyed by CI. Do not deploy this compose file or its privileged lab-only Redis processes outside CI. Reports are artifacts of the GitHub workflow.
