"""Synthetic negative contracts for complete live CRS include-graph observation."""
import copy
import unittest

import effective_ruleset_graph as graph
import runtime_ruleset_inventory as observed
from test_runtime_ruleset_inventory import tarball

P = "/etc/modsecurity.d/"
R = P + "owasp-crs/rules/"
FILES = {
    P+"modsecurity.conf": (
        b"SecRuleEngine On\n"
        b"Include /etc/modsecurity.d/owasp-crs/crs-setup.conf\n"
        b"Include /etc/modsecurity.d/owasp-crs/rules/*.conf\n"
    ),
    P+"owasp-crs/crs-setup.conf": b"SecAction id:100001,pass\n",
    R+"REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf": b"SecAction id:900100,pass\n",
    R+"REQUEST-930-APPLICATION-ATTACK-LFI.conf": b"SecAction id:930100,pass\n",
    R+"REQUEST-941-APPLICATION-ATTACK-XSS.conf": b"SecAction id:941100,pass\n",
    R+"REQUEST-942-APPLICATION-ATTACK-SQLI.conf": b"SecAction id:942100,pass\n",
    R+"REQUEST-949-BLOCKING-EVALUATION.conf": b"SecAction id:949100,pass\n",
}


class EffectiveRuntimeGraphTests(unittest.TestCase):
    def test_genuine_complete_include_graph_digest_matches_bounded_tar(self):
        digest, count = graph.walk_graph(FILES, P+"modsecurity.conf")
        zipped = tarball({
            "rules/" + path.removeprefix(R): raw
            for path, raw in FILES.items() if path.startswith(R)
        })
        self.assertEqual(digest, observed.canonical_rule_digest(zipped))
        self.assertEqual(count, 5)

    def test_nginx_mode_and_unambiguous_root_checked(self):
        config = (b"server {\n modsecurity on;\n modsecurity_rules_file "
                  b"/etc/modsecurity.d/modsecurity.conf;\n}")
        self.assertEqual(graph.root_from_nginx(config),P+"modsecurity.conf")
        for changed in (config.replace(b"on",b"off"),
                        config+b"\nmodsecurity off;",
                        config+b"\nmodsecurity_rules_file /etc/modsecurity.d/x.conf;",
                        config.replace(b"/etc/modsecurity.d/",b"/outside/"),
                        b"server { proxy_pass http://origin; }"):
            with self.subTest(changed=changed[:45]),self.assertRaises(ValueError):
                graph.root_from_nginx(changed)

    def test_no_missing_excluded_dangerous_rule_or_ambiguous_reinclude(self):
        for changed in (
            {k:v for k,v in FILES.items() if not k.endswith("REQUEST-941-APPLICATION-ATTACK-XSS.conf")},
            {**FILES,P+"modsecurity.conf":b"Include /etc/modsecurity.d/owasp-crs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf\n"},
            {**FILES,P+"modsecurity.conf":FILES[P+"modsecurity.conf"]+
             b"Include /etc/modsecurity.d/owasp-crs/rules/*.conf\n"},
            {**FILES,P+"owasp-crs/crs-setup.conf":b"Include /etc/modsecurity.d/modsecurity.conf\n"},
            {**FILES,P+"modsecurity.conf":b"IncludeOptional /etc/modsecurity.d/owasp-crs/rules/*.conf\n"},
            {**FILES,P+"modsecurity.conf":b"Include /etc/modsecurity.d/owasp-crs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf\n" +
             FILES[P+"modsecurity.conf"]}
        ):
            with self.subTest(changed=len(changed)),self.assertRaises(ValueError):
                graph.walk_graph(changed,P+"modsecurity.conf")

    def test_unreached_family_and_wrong_blocking_order_not_accepted(self):
        modified = dict(FILES)
        modified[R+"REQUEST-949-BLOCKING-EVALUATION.conf"] = b"SecAction id:949100,pass\n"
        # Bind files but arrange explicit include order putting anomaly
        # evaluation before SQLi classification. Never infer alphabetical
        # source order when the effective Include directives differ.
        modified[P+"modsecurity.conf"] = (
            b"Include /etc/modsecurity.d/owasp-crs/crs-setup.conf\n"
            b"Include /etc/modsecurity.d/owasp-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf\n"
            b"Include /etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf\n"
            b"Include /etc/modsecurity.d/owasp-crs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf\n"
            b"Include /etc/modsecurity.d/owasp-crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf\n"
            b"Include /etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf\n"
        )
        with self.assertRaisesRegex(ValueError, "order"):
            graph.walk_graph(modified,P+"modsecurity.conf")

    def test_path_traversal_case_alias_special_file_and_unreadable_risk(self):
        for invalid in ("/etc/modsecurity.d/../private.conf",
                        "/etc/modsecurity.d//rules/a.conf",
                        "/etc/modsecurity.d/./a.conf",
                        "/etc/modsecurity.d/x\\a.conf",
                        "/tmp/attacker.conf",
                        "/etc/modsecurity.d/☠.conf"):
            with self.subTest(invalid=invalid),self.assertRaises(ValueError):
                graph.valid_config_path(invalid)
        a=dict(FILES)
        a[P+"OWASP-CRS/crs-setup.conf"]=a[P+"owasp-crs/crs-setup.conf"]
        with self.assertRaisesRegex(ValueError, "case-aliased"):
            graph.walk_graph(a,P+"modsecurity.conf")
        a=dict(FILES)
        a[P+"extra.conf"]=b"x"*(graph.MAX_FILE+1)
        with self.assertRaises(ValueError):
            graph.walk_graph(a,P+"modsecurity.conf")

    def test_glob_does_not_match_nested_rule_paths(self):
        files = dict(FILES)
        files[R+"nested/REQUEST-944-HIDDEN.conf"]=b"SecRule id:944000\n"
        # Nested files are not a valid complete CRS rules directory.
        with self.assertRaises(ValueError):
            graph.walk_graph(files,P+"modsecurity.conf")


if __name__ == "__main__":
    unittest.main()
