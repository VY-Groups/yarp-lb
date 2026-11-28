import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from stage_candidate_handoff import stage, handoff_paths, mapping, ROOT
from stage_vip_tools import digest
from package_candidate import package
from extract_candidate import extract

class CandidateHandoff(unittest.TestCase):
    def test_both_archives_contain_exact_platform_handoff(self):
        sha="a"*40
        for rid,exe in (("win-x64","GatewayCoreYarp.exe"),("linux-x64","GatewayCoreYarp")):
            with self.subTest(rid=rid),tempfile.TemporaryDirectory() as temp:
                root=Path(temp)/"candidate";(root/"app").mkdir(parents=True)
                (root/"app"/exe).write_bytes(b"fixture")
                (root/"app/GatewayCoreYarp.dll").write_bytes(b"fixture")
                (root/"SOURCE_COMMIT.txt").write_text(sha)
                stage(root,rid)
                with self.assertRaises(ValueError): stage(root,rid)
                archive=Path(temp)/"archive";out=Path(temp)/"extracted"
                package(root,rid,sha,archive)
                extract(archive,out,sha,rid)
                self.assertEqual((out/"SOURCE_COMMIT.txt").read_text(),sha)
                for path in handoff_paths(rid):
                    self.assertEqual(digest(out/path),digest(root/path))
                for src,dest in mapping(rid).items():
                    self.assertEqual(digest(out/dest),digest(ROOT/src))
                self.assertFalse((out/"ops/ha"/("install-vip-service.sh" if rid=="win-x64" else "Install-VipService.ps1")).exists())
                with self.assertRaises(ValueError):
                    extract(archive,Path(temp)/"wrong-sha","b"*40,rid)
                (root/"README.md").unlink()
                incomplete=Path(temp)/"incomplete"
                package(root,rid,sha,incomplete)
                with self.assertRaisesRegex(ValueError,"handoff incomplete"):
                    extract(incomplete,Path(temp)/"bad",sha,rid)
    def test_existing_handoff_refused_without_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/"README.md").write_text("retain")
            with self.assertRaises(ValueError):stage(root,"win-x64")
            self.assertEqual((root/"README.md").read_text(),"retain")
            self.assertFalse((root/"ops").exists())
