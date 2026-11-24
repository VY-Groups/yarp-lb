# #51 — etcd quorum-backed authenticated WAF fencing lease (software verifier)

\`ops/waf/etcd_quorum_fence.py\` implements the live fencing contract
already required by \`ops/waf/two_node_transaction.py\`:

\`\`\`python
from etcd_quorum_fence import EtcdQuorumFence
from two_node_transaction import coordinate

fence = EtcdQuorumFence(
    fleet="waf-fleet-primary",
    endpoints=[
        {"url": "https://ETCD_MEMBER_A:2379", "leafSha256": "A"*64, "memberId": 1001},
        {"url": "https://ETCD_MEMBER_B:2379", "leafSha256": "B"*64, "memberId": 1002},
        {"url": "https://ETCD_MEMBER_C:2379", "leafSha256": "C"*64, "memberId": 1003},
    ],
    cluster_id="APPROVED_ETCD_NUMERIC_CLUSTER_ID",
    ca="/private/etcd/ca.pem",
    certificate="/private/etcd/waf-fence-reader.pem",
    key="/private/etcd/waf-fence-reader.key",
)
# This example cannot run until all placeholders are replaced, real TLS
# identities exist and independently authorized node adapters are provisioned.
# The existing coordinate(..., fence=fence) requires a fresh attestation at
# each preflight/apply/rollback/receipt boundary.
\`\`\`

The production API uses the etcd **v3 HTTP JSON gateway** on three
separately identified cluster members. Every member is accessed by direct
HTTPS with CA/hostname validation, an explicitly pinned server leaf SHA-256,
and a separately provisioned owner-private client certificate/key. Member
URLs, server leaf fingerprints and **independently approved numeric `memberId` values** must be distinct. Every linearizable response must identify the exact member ID pinned to that endpoint and leaf certificate; swapping backend member identity behind a valid TLS pin fails closed. The sample 1001/1002/1003 values are placeholders only, not verified member IDs.
A single API proxy, load-balancer alias, fake locally signed service or
static JSON file cannot count as a three-member quorum.

## Required external authority contract

A separate, privileged, independently reviewed etcd writer must use an
atomic **compare-and-swap** to create and renew one lease-attached key:

    /gatewaycore/waf/fence/<approved-fleet-id>

Its UTF-8 JSON value has exactly these keys:

    {
      "schemaVersion": 1,
      "kind": "waf",
      "nodeIds": ["node-a", "node-b"],
      "revision": 7,
      "policySha256": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "holder": "0123456789abcdef0123456789abcdef"
    }

The value is an illustrative schema, **not a granted production lease**.
The writer must be RBAC-separated from the read-only coordinator, bind its
key to a short renewable etcd lease (3–120 seconds, with at least three
seconds remaining at EACH check), serialize competing controllers under
etcd's consensus, persist monotonic fencing epochs via the KV
\`mod_revision\`, and prohibit unilateral rollback/lease reassignment.
Client readers must never possess writer RBAC/permissions.

On **every** phase the verifier makes two requests to EACH available member:
a **linearizable** (\`serializable:false\`) \`/v3/kv/range\` read of the
exact base64-encoded lease key followed by \`/v3/lease/timetolive\` for the
returned lease ID. It requires responses from at least **two of three**
different etcd member IDs, from the same independently pinned cluster,
with consistent KV modification revision, lease ID and holder. A responding
third member that disagrees is rejected rather than ignored. A minority
partition, expired or revoked lease, stale RDB replica, invalid TLS cert,
lease reassignment or different policy/node identity is **NO-GO**.
The initial lease identity is pinned for the entire transaction: acquiring
a new authority epoch cannot silently make a previously fenced controller
eligible again. A failed fencing check before rollback may intentionally
leave an unresolved manual reconciliation event; do not force rollback
without a valid lease.

### Software test (synthetic, not authoritative etcd cluster)

\`\`\`sh
python3 -m unittest discover -s ops/waf -p test_etcd_quorum_fence.py -v
\`\`\`

The synthetic tests simulate three distinct members, linearizable
reads, TTLs, a delayed late member crossing an earlier lease's expiry
deadline, one-member and two-member partitions, duplicate member IDs,
wrong cluster, tampering, revoked/expired lease and authority epoch
replacement. The verifier uses *current monotonic time at the final
quorum decision* so stale early answers cannot authorize mutation.

In addition, `.github/workflows/waf-etcd-quorum.yml` now runs
`tests/WafEtcd/real_quorum.py` against **three actual disposable
etcd v3.6 Raft processes** using a pinned upstream OCI digest, distinct
loopback-published client TLS endpoints, isolated Docker peer network,
temporary independently issued client/server PKI, live quorum
linearizable reads, actual server-side compare-and-swap, lease
revocation and a real 2-of-3 member outage. The test also verifies
that a competing CAS cannot change the active lease's creation/modification
revision, version, value or lease ID. The embedded etcd HTTP/gRPC
gateway requires server identities capable of both clientAuth and
serverAuth for its *internal* TLS connection; the disposable member
certificates therefore include both usages, while separate reader/writer
certificates remain clientAuth-only. The real CI test never exports
private keys or etcd logs.

These are **multiple processes on one disposable hosted Linux runner**,
not separate physical hosts or customer key custody, a production
quorum service, a remotely authenticated WAF agent rollout or a
production partition drill.

**Still required under #51 before closure:** an independently reviewed
lease-grant/CAS/renew authority with persistent writer fencing, independently operated real three-host etcd cluster network-partition test,
separate mutually authenticated **remote WAF node adapters which ALSO reject
fenced controllers at the mutation boundary**, two-node transactional
rollback with crash recovery, signed exception rendering/expiry/rollback,
representative customer native-audit FP/FN custody and matched sustained
Windows/Linux YARP+WAF performance acceptance. Real-site physical
survivability/headroom remains under #36. Neither a green fake-quorum test
nor this read-only verifier grants production GO or closes #51.
