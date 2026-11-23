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
- shadowEvidenceSha256: null for detect, approved uppercase digest for block
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
