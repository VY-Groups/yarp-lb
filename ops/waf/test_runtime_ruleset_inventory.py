"""Synthetic bounded Docker CRS inventory parser tests. No customer rules."""
import io
import tarfile
import unittest
import runtime_ruleset_inventory as observed

FILES = {
    "rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf": b"SecRule test930\n",
    "rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf": b"SecRule test941\n",
    "rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf": b"SecRule test942\n",
}

def tarball(files, links=(), extra=()):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for path, content in files.items():
            info = tarfile.TarInfo(path)
            info.mode = 0o644
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
        for path, dest in links:
            info = tarfile.TarInfo(path)
            info.type = tarfile.SYMTYPE
            info.linkname = dest
            archive.addfile(info)
        for path, content in extra:
            info = tarfile.TarInfo(path)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


class ObservedRuleInventoryTests(unittest.TestCase):
    def test_same_contents_are_canonical_despite_tar_order_and_metadata(self):
        first = observed.canonical_rule_digest(tarball(FILES))
        reverse = observed.canonical_rule_digest(tarball(dict(reversed(list(FILES.items())))))
        self.assertRegex(first, r"^[0-9A-F]{64}$")
        self.assertEqual(first, reverse)
        self.assertNotIn("SecRule", first)
        changed = {**FILES, "rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf":
                   b"SecRule test941 with extra condition\n"}
        self.assertNotEqual(first, observed.canonical_rule_digest(tarball(changed)))

    def test_missing_owasp_rule_family_fails_closed(self):
        for path in FILES:
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "rule family"):
                observed.canonical_rule_digest(tarball(
                    {k: v for k, v in FILES.items() if k != path}))

    def test_linked_file_and_path_traversal_fail_closed(self):
        for alias in ["rules/EXTRA.conf", "../rules/EXTRA.conf"]:
            with self.subTest(alias=alias), self.assertRaises(ValueError):
                observed.canonical_rule_digest(tarball(FILES, links=[
                    (alias, "/outside/private.conf")]))
        with self.assertRaises(ValueError):
            observed.canonical_rule_digest(tarball(
                FILES, extra=[("../escape.conf", b"bad")]))
        with self.assertRaises(ValueError):
            observed.canonical_rule_digest(tarball(
                FILES, extra=[("rules/../escape.conf", b"bad")]))
        for alias in ("rules//REQUEST-933-WEIRD.conf",
                      "rules/./REQUEST-933-WEIRD.conf",
                      "rules/REQUÊST-933-WEIRD.conf"):
            with self.subTest(alias=alias), self.assertRaisesRegex(
                    ValueError, "ambiguous"):
                observed.canonical_rule_digest(
                    tarball(FILES, extra=[(alias, b"SecRule bad\n")]))

    def test_duplicate_and_case_aliases_fail(self):
        first = next(iter(FILES))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            observed.canonical_rule_digest(tarball(
                FILES, extra=[(first.replace("REQUEST-", "request-", 1),
                               b"shadow-content")]))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            observed.canonical_rule_digest(tarball(
                FILES, extra=[(first, b"replacement")]))
        with self.assertRaisesRegex(ValueError, "case-aliased"):
            observed.canonical_rule_digest(tarball(
                FILES, extra=[(first.upper().replace("RULES", "rules"), b"shadow")]))

    def test_oversized_or_invalid_archive_is_not_a_valid_fingerprint(self):
        for raw in (b"", b"invalid tar", b"x" * (observed.MAX_ARCHIVE + 1)):
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                observed.canonical_rule_digest(raw)
        large = {**FILES,
                 "rules/REQUEST-900-OVERSIZED.conf": b"x" * (1024 * 1024 + 1)}
        with self.assertRaises(ValueError):
            observed.canonical_rule_digest(tarball(large))

    def test_docs_and_tar_mtime_not_part_of_crs_digest(self):
        first = observed.canonical_rule_digest(tarball(FILES))
        extra = tarball(FILES, extra=[
            ("rules/README.md", b"no runtime rule"),
        ])
        self.assertEqual(first, observed.canonical_rule_digest(extra))

    def test_untrusted_docker_id_and_limits_refused_before_subprocess(self):
        for ident in ("../abcdef", "NOT A HASH", "a" * 11, "a" * 65, ""):
            with self.subTest(ident=ident), self.assertRaises(ValueError):
                observed.limited_docker_copy(ident)
        with self.assertRaises(ValueError):
            observed.limited_docker_copy("a" * 64, limit=observed.MAX_ARCHIVE + 1)


if __name__ == "__main__":
    unittest.main()
