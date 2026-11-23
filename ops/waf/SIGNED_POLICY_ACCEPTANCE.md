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
- rulesetSha256: uppercase SHA-256 of frozen effective WAF ruleset
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

## Gated single-node mode activation and rollback (candidate software)

The optional Linux-only operator entrypoint at
\`ops/waf/rollout_controller.py\` is a narrowly scoped external Docker
Compose WAF **mode controller**. It is not an automatic production roll-out
service or a distributed two-host commit. It is supplied for disposable
software acceptance and an explicitly authorized operator run.

Before any mutation it requires the same signed policy (exact JSON bytes),
two distinct P-256 approval keys, independently held revision floor, real
approved shadow evidence when blocking, confirmed revision and a pinned
\`owasp/modsecurity-crs@sha256:...\` image. The proposed \`mode\` is taken from
the signed policy, never an independent unsigned CLI override. A signed
exception list is deliberately **REJECTED** until there is a verified
narrow-scope ModSecurity rendering/acceptance implementation; silently
ignoring an approved exception or applying a global rule bypass is unsafe.

The operator must separately establish the **actual effective ruleset
digest** used for the required \`--observed-ruleset-sha256\` input. The
controller DOES NOT independently derive this digest from the active
ModSecurity rule files. That provenance gap still blocks production #51
acceptance. A policy signed for the wrong rule set must not be activated.

The controller refuses an unpinned Compose WAF image, another published
origin service, host network exposure, privileged WAF, unknown runtime engine
mode or current image mismatch. It requires an already-running local WAF
whose loopback URL is \`http://127.0.0.1:<port>/\`. The dry-run performs
signature, image, Compose configuration, and live-image preflight; it
creates only a protected local interprocess lock, not a deployment.
\`--execute\` enables an explicitly approved single-node change.

On execution, it first checks baseline benign/XSS HTTP behavior. It
recreates only the \`waf\` service using the approved \`On\` or
\`DetectionOnly\` mode, then checks the new live Docker image ID, observed
engine mode and benign/XSS outcomes. On **any** apply, verification or
audit-receipt write failure, it tries to restore and recheck the previous
mode. A private JSON result distinguishes applied, verified rollback, and
rollback failure; even a verified rollback exits nonzero. Receipts are
new-only, 0600, fsynced files under an operator-owned 0700 Linux directory;
they are not uploaded to CI, and prior receipts are never overwritten.

Example *illustrative only* (paths and evidence must be independently
provisioned, not committed):

\`\`\`sh
python3 ops/waf/rollout_controller.py \
  --policy /private/waf/policy.json \
  --approval /private/waf/reviewer-one.json \
  --approval /private/waf/reviewer-two.json \
  --reviewer-key reviewer-one=/secure/waf/reviewer-one.pem \
  --reviewer-key reviewer-two=/secure/waf/reviewer-two.pem \
  --minimum-revision-file /secure/waf/revision-floor.txt \
  --observed-ruleset-sha256 REPLACE_WITH_VERIFIED_EFFECTIVE_RULESET_SHA256 \
  --shadow-evidence-file /private/waf/approved-shadow.json \
  --compose /private/waf/compose.yml \
  --image owasp/modsecurity-crs@sha256:REPLACE_WITH_PINNED_64_HEX_DIGEST \
  --health-url http://127.0.0.1:18888/ \
  --receipt /private/waf/receipts/revision-43.json \
  --confirm-revision 43
# Add --execute ONLY after a separate authorized change approval.
\`\`\`

**Unqualified and intentionally unsupported:** rendering signed exact-route
exceptions, cryptographic attestation of active CRS rule files, active
distributed two-node canary/quorum/fencing, atomic cross-node rollback,
automated independent trust-floor advancement, container TLS ingress,
client identity, external immutable audit collection, private customer
corpus, per-route FP/FN, sustained throughput/p99/CPU and Windows service
integration. Do not bypass those requirements to close #51. A successful
local mode switch is NOT a production-GO decision; actual site #36
requires separately executed evidence. The adapter makes no network call
outside the operator-chosen literal 127.0.0.1 HTTP endpoint and local
Docker Engine commands.

