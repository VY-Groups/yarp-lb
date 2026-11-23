"""Negative and positive offline tests for Speedscope allocation-stack evidence."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

MODULE = Path(__file__).with_name("verify_speedscope.py")
SPEC = importlib.util.spec_from_file_location("verify_speedscope", MODULE)
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


def sampled():
    return {"shared": {"frames": [{"name": "Gateway.Proxy"}]},
            "profiles": [{"type": "sampled", "samples": [[0]], "weights": [1]}]}


class SpeedscopeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "profile.speedscope.json"

    def check(self, obj):
        self.path.write_text(json.dumps(obj), encoding="utf-8")
        return VERIFY.verify(self.path)

    def test_real_sampled_stack_required(self):
        self.assertEqual(self.check(sampled())["stack_observations"], 1)

    def test_real_evented_open_required(self):
        evented = {"shared": {"frames": [{"name": "Gateway.Proxy"}]},
                   "profiles": [{"type": "evented",
                                 "events": [{"type": "O", "frame": 0, "at": 0},
                                            {"type": "C", "frame": 0, "at": 1}]}]}
        self.assertEqual(self.check(evented)["stack_observations"], 1)

    def test_empty_or_missing_profiles_rejected(self):
        for obj in ({}, {"shared": {"frames": [{"name": "f"}]}, "profiles": []},
                    {"shared": {"frames": []}, "profiles": [{"type": "sampled",
                                                            "samples": [[0]]}]}):
            with self.subTest(obj=obj):
                with self.assertRaisesRegex(ValueError, "no shared frames or profiles"):
                    self.check(obj)

    def test_valid_json_but_no_observed_stack_rejected(self):
        obj = sampled()
        obj["profiles"][0]["samples"] = [[], []]
        with self.assertRaisesRegex(ValueError, "no stack observations"):
            self.check(obj)

    def test_bogus_frame_references_rejected(self):
        for value in (-1, 1, True, "0"):
            obj = sampled()
            obj["profiles"][0]["samples"] = [[value]]
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "frame reference"):
                    self.check(obj)

    def test_malformed_event_rejected(self):
        obj = sampled()
        obj["profiles"] = [{"type": "evented",
                            "events": [{"type": "O", "frame": 999}]}]
        with self.assertRaisesRegex(ValueError, "frame reference"):
            self.check(obj)

    def test_unsupported_profile_type_rejected(self):
        obj = sampled()
        obj["profiles"][0]["type"] = "unknown"
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            self.check(obj)

    def test_missing_file_rejected(self):
        with self.assertRaises(OSError):
            VERIFY.verify(self.path)


if __name__ == "__main__":
    unittest.main()
