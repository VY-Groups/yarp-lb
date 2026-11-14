"""Repository-wide organization branding regression. No vendor package renaming."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
# Compose legacy words rather than embedding a prohibited full brand in
# source. Match joined, spaced, dashed and underscore variants.
OLD = re.compile("speed" + r"[\s_-]*" + "sign" + "|" + "speed" + "sg" + "|" + "ss" + "tpl" + "|" + "VY" + r"[-_\s]*" + "Groups" + "|" + "Nex" + "ora", re.I)
SKIP = {".git", "bin", "obj", "node_modules", ".venv", "__pycache__"}
FILES = [p for p in ROOT.rglob("*")
         if p.is_file() and not SKIP.intersection(p.relative_to(ROOT).parts)]

class NeutralBrandTests(unittest.TestCase):
    def test_no_legacy_brand_in_repository_paths(self):
        bad = [p.relative_to(ROOT).as_posix() for p in FILES
               if OLD.search(p.relative_to(ROOT).as_posix())]
        self.assertEqual(bad, [], "Unrenamed organization-branded path")
    def test_no_legacy_brand_inside_source_or_documentation(self):
        errors = []
        for file in FILES:
            # Binary fixtures are ignored, not deployment code.
            try:
                data=file.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            match=OLD.search(data)
            if match:
                errors.append({"path":file.relative_to(ROOT).as_posix(),
                               "line":data.count("\n",0,match.start())+1})
        self.assertEqual(errors, [], "Legacy brand still exists in tracked text")
    def test_real_project_names_and_units_are_consistent(self):
        self.assertTrue((ROOT/"control-center/GatewayCoreYarp.csproj").is_file())
        self.assertTrue((ROOT/"control-center/GatewayAgent/GatewayCoreGatewayAgent.csproj").is_file())
        self.assertEqual(
            (ROOT/"control-center/ops/systemd/gatewaycore-yarp.service").read_text(),
            (ROOT/"ops/systemd/gatewaycore-yarp.service").read_text())
        unit=(ROOT/"ops/systemd/gatewaycore-yarp.service").read_text()
        self.assertIn("/GatewayCoreYarp.dll",unit)
        self.assertIn("AmbientCapabilities=CAP_NET_BIND_SERVICE",unit)
    def test_workflows_target_real_renamed_projects(self):
        for path in (".github/workflows/control-center-ci.yml",
                     ".github/workflows/ec2-real-control-center.yml",
                     ".github/workflows/listener-isolation.yml"):
            text=(ROOT/path).read_text()
            self.assertIn("GatewayCoreYarp",text)
            self.assertNotRegex(text,OLD)

if __name__=="__main__":
    unittest.main()
