import tempfile
import unittest
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from package_candidate import package,sha256
class PackageCandidate(unittest.TestCase):
    def test_both_platforms_and_checksum(self):
        for rid,exe in (("linux-x64","GatewayCoreYarp"),("win-x64","GatewayCoreYarp.exe")):
            with self.subTest(rid=rid), tempfile.TemporaryDirectory() as t:
                root=Path(t)/"candidate";out=Path(t)/"out"
                (root/"app").mkdir(parents=True)
                (root/"SOURCE_COMMIT.txt").write_text("a"*40)
                (root/"app"/exe).write_bytes(b"test executable")
                (root/"app"/"GatewayCoreYarp.dll").write_bytes(b"test assembly")
                package(root,rid,"a"*40,out)
                digest,name=(out/"SHA256SUMS.txt").read_text().split()
                self.assertEqual(digest,sha256(out/name))
                (root/"app"/"private.pfx").write_bytes(b"fixture only")
                with self.assertRaises(ValueError):
                    package(root,rid,"a"*40,Path(t)/"other")
