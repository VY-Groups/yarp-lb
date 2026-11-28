import tempfile
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stage_vip_tools import stage, ROOT, digest
from package_candidate import package

class VipTools(unittest.TestCase):
    def test_platform_allowlist_and_no_overwrite(self):
        for rid, tool in (("win-x64","Install-VipService.ps1"),("linux-x64","install-vip-service.sh")):
            with self.subTest(rid=rid), tempfile.TemporaryDirectory() as temp:
                root=Path(temp)/"candidate"; root.mkdir()
                stage(root,rid)
                folder=root/"ops/ha"
                self.assertEqual({p.name for p in folder.iterdir()}, {tool,"ADC_DISTRIBUTED_VIP_ADMISSION.md"})
                self.assertEqual(digest(folder/tool),digest(ROOT/"ops/ha"/tool))
                with self.assertRaises(ValueError): stage(root,rid)
                (root/"app").mkdir()
                exe="GatewayCoreYarp.exe" if rid=="win-x64" else "GatewayCoreYarp"
                (root/"app"/exe).write_bytes(b"fixture")
                (root/"app/GatewayCoreYarp.dll").write_bytes(b"fixture")
                (root/"SOURCE_COMMIT.txt").write_text("a"*40)
                package(root,rid,"a"*40,Path(temp)/"archive")
    def test_reject_linked_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/"candidate";root.mkdir()
            outside=Path(temp)/"outside";outside.mkdir()
            try:(root/"ops").symlink_to(outside,target_is_directory=True)
            except OSError:self.skipTest("symlink not supported by test identity")
            with self.assertRaises(ValueError):stage(root,"linux-x64")
            self.assertEqual(list(outside.iterdir()),[])
