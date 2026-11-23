#!/usr/bin/env python3
"""CI artifact allowlist: never publish raw WAF logs or operator fixtures.

This test runs before Docker so a future broad artifact path fails even if
the WAF lab otherwise passes. Uploaded file paths are deliberately exact.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/waf-crs-acceptance.yml"

ALLOWED = frozenset({
    "artifacts/waf-crs/benchmark-direct.json",
    "artifacts/waf-crs/benchmark-proxy-only.json",
    "artifacts/waf-crs/benchmark-blocking.json",
    "artifacts/waf-crs/benchmark-detection.json",
    "artifacts/waf-crs/benchmark-restored.json",
    "artifacts/waf-crs/benchmark-summary.json",
    "artifacts/waf-crs/blocking-corpus-report.json",
    "artifacts/waf-crs/detection-corpus-report.json",
    "artifacts/waf-crs/waf-image-id.txt",
    "artifacts/waf-crs/waf-image-digests.json",
    "artifacts/waf-crs/waf-selected-image.txt",
    "artifacts/waf-crs/backend-bindings.json",
})


def artifact_paths(workflow_text):
    marker = "- name: Upload allowlisted synthetic WAF evidence (no raw logs or private corpus)"
    if workflow_text.count(marker) != 1:
        raise ValueError("exactly one protected WAF artifact upload step is required")
    step = workflow_text.split(marker, 1)[1]
    if step.count("uses: actions/upload-artifact@v4") != 1:
        raise ValueError("protected upload step is missing or ambiguous")
    match = re.search(r"(?m)^          path: \|\n((?:            [^\n]+\n)+)", step)
    if not match:
        raise ValueError("expected explicit multiline WAF artifact file allowlist")
    names = [line.strip() for line in match.group(1).splitlines()]
    if len(names) != len(set(names)):
        raise ValueError("duplicate WAF upload entries")
    return frozenset(names)


class WafCiArtifactContractTests(unittest.TestCase):
    def test_only_fixed_synthetic_evidence_is_uploaded(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(ALLOWED, artifact_paths(source))
        self.assertNotIn("path: artifacts/waf-crs/", source)

    def test_private_corpus_and_raw_logs_cannot_match_upload_allowlist(self):
        uploaded = artifact_paths(WORKFLOW.read_text(encoding="utf-8"))
        for private_name in (
            "artifacts/waf-crs/operator-corpus-report.json",
            "artifacts/waf-crs/docker-compose.log",
            "artifacts/waf-crs/blocking-audit.log",
            "artifacts/waf-crs/detection-only-audit.log",
            "artifacts/waf-crs/xss-response.txt",
            "artifacts/waf-crs/benign-cert.der",
            "artifacts/waf-crs/pkix-der-response.json",
        ):
            with self.subTest(private_name=private_name):
                self.assertNotIn(private_name, uploaded)

    def test_fail_closed_when_someone_reintroduces_a_directory_or_glob(self):
        example = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotEqual(
            ALLOWED, artifact_paths(example.replace(
                "artifacts/waf-crs/benchmark-direct.json",
                "artifacts/waf-crs/**")))
        self.assertNotEqual(
            ALLOWED, artifact_paths(example.replace(
                "artifacts/waf-crs/benchmark-direct.json",
                "artifacts/waf-crs/operator-corpus-report.json")))


if __name__ == "__main__":
    unittest.main()
