# Signed external WAF policy preflight — software only

This tool checks a proposed external WAF policy before a separately authorized
deployment. It is READ-ONLY: it does not render, activate, apply, roll back or
even contact a ModSecurity instance. A PASS is not proof of policy activation,
actual WAF verdict provenance, customer corpus acceptance or production GO.

## Policy schema

Provide one UTF-8 JSON policy with exactly these fields:

- schemaVersion: integer 1
- revision: positive monotonically increasing integer; must exceed a trusted
  minimum revision stored OUTSIDE the candidate policy directory
- mode: detect or block
- rulesetSha256: uppercase canonical SHA-256 of the observed CRS `.conf` file subtree described below; NOT a complete effective Nginx/ModSecurity include-graph attestation
- shadowEvidenceSha256: null for detect, approved uppercase digest for block.
  A blocking-mode invocation MUST additionally supply --shadow-evidence-file
  pointing to the exact private evidence bytes. Their computed SHA-256 must
  match this signed digest; an asserted digest string is never sufficient.
- issuedAtUtc, expiresAtUtc: canonical UTC timestamps, max 45-day lifespan
- exceptions: <=64 entries with exceptionId, owner, reason, routeId, httpMethod,
  path, contentType, ruleId, issuedAtUtc, expiresAtUtc. Each exception is bound
  to one exact literal path, exact method/type/rule and owned route; no wildcard,
  encoded path, query, dot-segment or broad bypass; max 30-day lifetime.

The supplied observed effective ruleset SHA-256 and WAF mode must match.
The operator must collect these from the actual locked-down WAF instance;
passing fabricated CLI observations is not independent verification.

Two distinct independent approvers each provide a detached signed approval
with exact JSON keys schemaVersion=1, reviewer, policySha256, signedAtUtc,
signatureBase64. The signature is DER P-256/SHA-256 over EXACT UTF-8 bytes:

    GatewayCore.WAF.Review.v1\n
    <UPPERCASE SHA-256 of exact policy JSON bytes>\n
    <reviewer ID>\n
    <signedAtUtc>\n

Here \n denotes one newline, with no empty lines between fields. The
signatures are verified against independent operator-provisioned SPKI PEM
public keys. Never commit reviewer signing private keys or customer policies.
The verifier fails on duplicate/case-alias fields, missing signatures,
same-key double approval, changed policy, expired approvals or broad bypasses.

## Authorized read-only execution

    python3 ops/waf/verify_signed_policy.py \
      --policy /private/candidate/policy.json \
      --approval /private/candidate/reviewerA.json \
      --approval /private/candidate/reviewerB.json \
      --reviewer-key reviewerA=/secure/approval-root/reviewerA.pem \
      --reviewer-key reviewerB=/secure/approval-root/reviewerB.pem \
      --minimum-revision-file /secure/approval-root/current-revision \
      --observed-ruleset-sha256 REPLACE_WITH_REAL_UPPERCASE_SHA256 \
      --observed-mode detect

For a blocking-mode proposal, use --observed-mode block and add
--shadow-evidence-file /private/approved/shadow-evidence.json. A missing,
swapped or mismatched file fails closed. This verifies file-to-approval digest
binding, not independent provenance of any verdict inside the evidence file.

The minimum revision and trust anchors must remain independently protected
outside the restored candidate policy tree. Only absolute, single-link
regular input files are accepted and changed opened inodes are rejected.
A privileged concurrent attacker modifying the directory ancestors is NOT
within the guarantee: trusted parent directories need independent OS ACLs.

An authorized deployment controller, NOT this script, must separately run
detect-only evidence review, transactional two-host apply/rollback, signer
and revision consistency checks, stored audit receipts, and then advance
the trusted revision monotonically after successful commit. Do not use this
as a stand-alone production deployment mechanism.

## Evidence

    python3 -m unittest discover -s ops/waf -p test_verify_signed_policy.py -v

CI uses Python 3.12 and OpenSSL on a disposable Ubuntu GitHub runner and
creates temporary P-256 signers. It covers positive detect/block signing,
rollback, tampered policy, duplicated signer, broad/expired exceptions,
invalid rule digest/mode and unsafe file aliases. It does NOT prove Windows
WAF integration, real customer FP/FN, operational false-positive tuning,
p95/p99/CPU, policy rollback on hosts, physical failover, or #51 closure.
Real environment acceptance stays under #36.


## Runtime effective ModSecurity include graph evidence (not image trust)

\`ops/waf/effective_ruleset_graph.py\` is an additional **fail-closed,
read-only** runtime check for the pinned Nginx/ModSecurity CRS Docker image.
It requires one unambiguous enabled ModSecurity entrypoint found in
\`nginx -T\`, reads existing \`/etc/modsecurity.d\` config files only through
bounded Docker execution (no shell), and resolves actual static \`Include\`
directives and narrowly scoped one-directory \`*.conf\` globs. It rejects
path traversal, unapproved aliases, arbitrary symlinked rule subtrees,
missing/cyclic/duplicate includes, unresolved optional/dynamic directives, absent critical
930/941/942 attack families, and anomaly evaluation that occurs before its
setup/attack rules.

The reviewed pinned Docker image uses exactly one known alias:
`/etc/modsecurity.d/owasp-crs` must resolve to `/opt/owasp-crs`.
The runtime inspector checks that exact pair and refuses any other symlink
under `/etc/modsecurity.d`; it follows only this verified alias to enumerate
the effective .conf files. Empty non-CRS wrapper files can be present in the
image, but empty real CRS rule files remain prohibited. These exceptions
are image-layout compatibility rules, not an operator-authorized writable
filesystem or arbitrary symlink permission.

The required set of included CRS file bytes is re-hashed using the same
canonical domain as \`runtime_ruleset_inventory.py\`. The result must match
the separately observed, bounded Docker-copied CRS inventory. Hashing file
bytes by itself is insufficient: a missing or disabled include can give an
apparently valid but unused CRS inventory. This check strengthens observed
include reachability rather than merely hashing files on disk. Run only
on a disposable immutable-reviewed image, or on an independently authorized
running WAF node, with a literal container ID:

\`\`\`sh
python3 -m unittest discover -s ops/waf -p test_effective_ruleset_graph.py -v
python3 ops/waf/effective_ruleset_graph.py --container \
  <A_VERIFIED_LITERAL_DOCKER_CONTAINER_HEX_ID>
\`\`\`

The existing WAF Docker CI now runs the actual live graph gate **before**
benign/malicious request acceptance. It never uploads or prints raw Nginx
configuration, ModSecurity content, private request bodies, credentials or
runtime paths. It prints only a synthetic/pass/fail signal and the canonical
rule digest. External Nginx distributions whose graph cannot be resolved
must explicitly remain unsupported until the graph parser is reviewed and
compatible. Do not bypass a failed check by trusting an image tag alone.

**Scope limitation:** Even real include-graph reachability does not certify
the upstream image signing chain, complete evaluation of all possible
conditional Nginx location overrides, tenant origin isolation, native WAF
event custody, reviewer-signed policy ownership, future rule updates,
cross-node fencing/rollback, per-route customer FP/FN rates or actual
Windows/Linux sustained throughput. The externally managed WAF remains
optional integration; this gate alone does not close #51 and does not
satisfy the physical site test under #36.

## Two-node fenced transaction core (software candidate; not production fleet)

\`ops/waf/two_node_transaction.py\` implements a security-oriented,
**two-node coordinator core** for two independently validated WAF adapters.
It accepts only a policy/ruleset digest that was separately verified against
the signed P-256 policy and requires a live, independently authenticated
fencing authority supplied by an external controller. There is **no**
self-approved fence, unsigned CLI bypass, or fake local quorum fallback.

The coordinator preflights **both** nodes (baseline mode, image, observed
CRS bytes, prior HTTP smoke and target configuration) before changing either,
requires matching baseline modes and identical pinned image digests, and
writes a new-only private/fsynced intent record before the first mutation.
Each activation rechecks the live fence and both nodes' runtime state,
verifies unchanged image/rules and observed allow/block behavior after the
actual apply. A timeout that occurs *after* remote mutation still requires
compensation on both nodes. A failed activation, expired external fencing
lease, changed image/CRS or missing final receipt triggers compensating
rollback of **both** nodes to their original configuration. The private
failure receipt records per-node rollback success/failure, never raw
request bodies, credentials or private evidence. Unreconciled intents block
replay. The trusted policy revision is **not** advanced automatically.

\`\`\`sh
python3 -m unittest discover -s ops/waf -p test_two_node_transaction.py -v
\`\`\`

**This is not a standalone deployment command**: it intentionally requires
actual authenticated remote adapters and a **renewable, monotonic
partition-fencing authority**, which have not yet been connected to the
software core. It is NOT an atomic cross-host transaction. Crashes or network
partitions after the first activation can leave mixed states; the protected
intent must be reconciled under independently verified fencing before retry.
In-process fake nodes validate software compensation paths only, not physical
host recovery. No production capability or issue #51 closure should be
inferred from the local protocol tests. Real two-host network isolation
and site-specific traffic/capacity acceptance belong to #36; authenticated
remote execution/quorum/software-integrated rollout still belong to #51.


## Gated single-node mode activation and rollback (candidate software)

The optional Linux-only operator entrypoint at
`ops/waf/rollout_controller.py` is a narrowly scoped external Docker
Compose WAF **mode controller**. It is not an automatic production roll-out
service or a distributed two-host commit. It is supplied for disposable
software acceptance and an explicitly authorized operator run.

Before any mutation it requires the same signed policy (exact JSON bytes),
two distinct P-256 approval keys, independently held revision floor, real
approved shadow evidence when blocking, confirmed revision and a pinned
`owasp/modsecurity-crs@sha256:...` image. The proposed `mode` is taken from
the signed policy, never an independent unsigned CLI override. A signed
exception list is deliberately **REJECTED** until there is a verified
narrow-scope ModSecurity rendering/acceptance implementation; silently
ignoring an approved exception or applying a global rule bypass is unsafe.

The operator must obtain the **canonical SHA-256 digest of the observed
CRS `.conf` files inside the actual running WAF container**, NOT type a
self-asserted or arbitrary hash. To get this bounded read-only inventory:

```sh
container_id="$(docker compose -f /private/waf/compose.yml ps -q waf)"
python3 ops/waf/runtime_ruleset_inventory.py --container "$container_id"
```

The fixed canonical domain `GatewayCore.WAF.ObservedCRSRuleFiles.v1` hashes
the sorted exact relative path and content bytes of regular, nonlinked tar
`/etc/modsecurity.d/owasp-crs/rules/*.conf`. Archive size, individual
files, total bytes, path aliasing, ambiguous duplicate names and the
presence of 930/941/942 CRS families are all fail-closed. The policy
`rulesetSha256` MUST contain that exact uppercase SHA-256, and both
detached P-256 reviewer signatures MUST cover those policy bytes.

The controller independently re-observes the actual running container's
rules before any activation, after a change, and during rollback, rejecting
any mismatch with the signed digest. A caller repeating a fabricated
`--observed-ruleset-sha256` cannot turn it into observed file evidence.
CI proves this with cryptographically valid reviewers signing a false
rule tree hash.

**Limit:** File-byte observation is not cryptographic attestation of the
runtime's **complete effective include graph**: an Nginx/modsecurity
configuration could omit or override a file, inject a directive from
another include path, or alter mounted files elsewhere. Separate signed
effective-configuration, mounted exception and immutable image
verification remains required for production #51 acceptance.

The controller refuses an unpinned Compose WAF image, another published
origin service, host network exposure, privileged WAF, unknown runtime engine
mode or current image mismatch. It requires an already-running local WAF
whose loopback URL is `http://127.0.0.1:<port>/`. The dry-run performs
signature, image, Compose configuration, and live-image preflight; it
creates only a protected local interprocess lock, not a deployment.
`--execute` enables an explicitly approved single-node change.

On execution, it first checks baseline benign/XSS HTTP behavior. It
recreates only the `waf` service using the approved `On` or
`DetectionOnly` mode, then checks the new live Docker image ID, observed
engine mode and benign/XSS outcomes. On **any** apply, verification or
audit-receipt write failure, it tries to restore and recheck the previous
mode. A private JSON result distinguishes applied, verified rollback, and
rollback failure; even a verified rollback exits nonzero. Receipts are
new-only, 0600, fsynced files under an operator-owned 0700 Linux directory;
they are not uploaded to CI, and prior receipts are never overwritten.

Example *illustrative only* (paths and evidence must be independently
provisioned, not committed):

```sh
python3 ops/waf/rollout_controller.py \
  --policy /private/waf/policy.json \
  --approval /private/waf/reviewer-one.json \
  --approval /private/waf/reviewer-two.json \
  --reviewer-key reviewer-one=/secure/waf/reviewer-one.pem \
  --reviewer-key reviewer-two=/secure/waf/reviewer-two.pem \
  --minimum-revision-file /secure/waf/revision-floor.txt \
  --observed-ruleset-sha256 REPLACE_WITH_OBSERVED_CANONICAL_CRS_RULE_FILES_SHA256 \
  --shadow-evidence-file /private/waf/approved-shadow.json \
  --compose /private/waf/compose.yml \
  --image owasp/modsecurity-crs@sha256:REPLACE_WITH_PINNED_64_HEX_DIGEST \
  --health-url http://127.0.0.1:18888/ \
  --receipt /private/waf/receipts/revision-43.json \
  --confirm-revision 43
# Add --execute ONLY after a separate authorized change approval.
```

## Narrow signed WAF exception configuration candidate (offline only)

`ops/waf/render_signed_exceptions.py` now transforms a **fully verified**
two-reviewer P-256 policy into one protected, non-overwritten ModSecurity
configuration *candidate*. It repeats the complete signed-policy and
independent trust/revision checks before reading the accepted policy bytes,
compares those bytes to both approved policy digests, and refuses any
unapproved scope. It does not alter a running container, replace an active
configuration, or advance the independent revision floor.

The initial supported carve-out is deliberately limited to **CRS 920420**
for **POST**, exact **application/pkix-cert** and a nonroot, canonical ASCII
path. GET, arbitrary rule IDs (including XSS/SQLi), encoded/aliased paths,
duplicate effective scopes, unsupported MIME types and unsafe output paths
fail closed. The generated chain requires `TIME_EPOCH` within the signed
UTC issue/expiry window, exact request method, **raw URI** and media type
before removing that single CRS rule for that request; it does not weaken
the global anomaly threshold or remove an entire rule family.

Example (operator must supply private, genuine review/evidence files; do not
use fixture keys or policy in a real environment):

```sh
python3 ops/waf/render_signed_exceptions.py \
  --policy /private/waf/candidate/policy.json \
  --approval /private/waf/candidate/review-a.json \
  --approval /private/waf/candidate/review-b.json \
  --reviewer-key reviewerA=/secure/waf/reviewer-a.pub \
  --reviewer-key reviewerB=/secure/waf/reviewer-b.pub \
  --minimum-revision-file /secure/waf/accepted-revision \
  --observed-ruleset-sha256 REPLACE_WITH_ACTUAL_OBSERVED_DIGEST \
  --observed-mode detect \
  --out /private/waf/generated/scoped-exception-rev7.conf
```

Use a separate private pathname for every new candidate. Output is a
new-only, fsynced 0600 file in an operator-owned 0700 directory. Review the
rendered SHA-256, signed exception scope, actual inclusion order, live
ModSecurity parser behavior, expiry and rollback before anyone mounts the
candidate. In particular this feature **does not implement** an authenticated
two-host transaction, live include-graph attestation, atomic fleet activation,
automatic policy expiration removal, independent audit storage or production
rollback. A request-time expiry condition still requires an independent
integration test on the exact deployed runtime. #51 remains OPEN until
signed deployment and all performance/evidence acceptance are complete.

Run the new disposable cryptographic and rendering regressions:

```sh
python3 -m unittest discover -s ops/waf -p test_render_signed_exceptions.py -v
```

**Unqualified and intentionally unsupported:** rendering signed exact-route
exceptions, cryptographic attestation of the full effective configuration/include graph, active
distributed two-node canary/quorum/fencing, atomic cross-node rollback,
automated independent trust-floor advancement, container TLS ingress,
client identity, external immutable audit collection, private customer
corpus, per-route FP/FN, sustained throughput/p99/CPU and Windows service
integration. Do not bypass those requirements to close #51. A successful
local mode switch is NOT a production-GO decision; actual site #36
requires separately executed evidence. The adapter makes no network call
outside the operator-chosen literal 127.0.0.1 HTTP endpoint and local
Docker Engine commands.

