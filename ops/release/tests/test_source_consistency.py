import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]

class ReleaseSourceConsistency(unittest.TestCase):
    def test_single_canonical_systemd_source(self):
        self.assertEqual(
            (ROOT/'ops/systemd/speedsign-yarp.service').read_text(),
            (ROOT/'control-center/ops/systemd/speedsign-yarp.service').read_text()
        )
    def test_no_obsolete_readiness_or_redis_p0_claims(self):
        doc=(ROOT/'control-center/docs/ONPREM_PRODUCTION_GO_GATES.md').read_text()
        self.assertIn('/gateway/health/ready',doc)
        self.assertIn('PRODUCTION NO-GO',doc)
        self.assertIn('no Redis requirement',doc)
        self.assertNotIn('there is no /gateway/health/ready',doc.lower())
    def test_privileged_bind_and_nonroot_service(self):
        u=(ROOT/'ops/systemd/speedsign-yarp.service').read_text()
        self.assertIn('AmbientCapabilities=CAP_NET_BIND_SERVICE',u)
        self.assertIn('CapabilityBoundingSet=CAP_NET_BIND_SERVICE',u)
        self.assertIn('User=speedsg-gateway',u)
        self.assertNotIn('User=root',u)

if __name__=='__main__':unittest.main()
