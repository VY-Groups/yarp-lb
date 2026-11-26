import hashlib
import json
import socket
import ssl
import tempfile
import threading
from types import SimpleNamespace
from pathlib import Path
import unittest
from unittest import mock
import specialist_tls_broker as broker
import test_mtls_fenced_node as node_fixture

class SpecialistBrokerTests(unittest.TestCase):
    def test_peer_pin_is_exact(self):
        connection = mock.Mock()
        connection.getpeercert.return_value = b"leaf"
        self.assertTrue(broker.pinned_peer(connection, hashlib.sha256(b"leaf").hexdigest().upper()))
        self.assertFalse(broker.pinned_peer(connection, "0"*64))
        connection.getpeercert.return_value = None
        self.assertFalse(broker.pinned_peer(connection, "0"*64))

    def test_dns_only_exact_plan_and_explicit_execute(self):
        plan = ([object(), object()], {"example.test": 1}, Path("/private/journal"), 7, "A"*64)
        request = {"operation":"preflight","revision":7,"digest":"A"*64}
        with mock.patch.object(broker.dns,"preflight") as pre, mock.patch.object(broker.dns,"Journal") as journal, mock.patch.object(broker.dns,"execute") as execute:
            self.assertEqual(broker.dispatch_dns(json.dumps({**request,"digest":"B"*64}).encode(),plan),"refused-or-failed")
            self.assertEqual(broker.dispatch_dns(json.dumps({**request,"path":"/tmp/x"}).encode(),plan),"refused-or-failed")
            pre.assert_not_called()
            self.assertEqual(broker.dispatch_dns(json.dumps(request).encode(),plan),"preflight-only")
            execute.assert_not_called()
            journal.assert_not_called()
            self.assertEqual(broker.dispatch_dns(json.dumps({**request,"operation":"execute"}).encode(),plan),"applied-uncommitted")
            execute.assert_called_once()
            journal.assert_called_once_with(plan[2])

    def test_dns_preflight_failure_never_mutates(self):
        plan = ([], {}, Path("/private/journal"), 7, "A"*64)
        raw = json.dumps({"operation":"execute","revision":7,"digest":"A"*64}).encode()
        with mock.patch.object(broker.dns,"preflight",side_effect=ValueError()), mock.patch.object(broker.dns,"execute") as execute:
            self.assertEqual(broker.dispatch_dns(raw,plan),"refused-or-failed")
            execute.assert_not_called()

class RealSpecialistTransportTests(unittest.TestCase):
    def test_tls_identity_frame_and_dispatch_boundary(self):
        with tempfile.TemporaryDirectory(prefix="specialist-broker-mtls-") as temp:
            # Reuse the disposable CA fixture from the existing real WAF test,
            # but exercise the actual shipping specialist TCP server.
            root = Path(temp)
            ca, certs = node_fixture.NodeTests.identities(SimpleNamespace(root=root))
            server_cert, server_key, server_pin = certs["server-a"]
            client_cert, client_key, client_pin = certs["client"]
            args = SimpleNamespace(bind="127.0.0.1", port=0,
                server_certificate=server_cert, server_key=server_key,
                client_ca=ca, client_sha256=client_pin)
            # Production listener still refuses port zero. Reserve a test port
            # and immediately bind the same address through the shipping code.
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1",0))
                args.port = reservation.getsockname()[1]
            dispatch = mock.Mock(return_value="preflight-only")
            with broker.create_server(args, dispatch) as server:
                worker = threading.Thread(target=server.serve_forever,
                    kwargs={"poll_interval":.02}, daemon=True)
                worker.start()
                try:
                    def exchange(identity, frame, pin=server_pin, hostname="127.0.0.1"):
                        context = ssl.create_default_context(cafile=ca)
                        if identity:
                            context.load_cert_chain(*certs[identity][:2])
                        with socket.create_connection(server.server_address, timeout=3) as connection:
                            with context.wrap_socket(connection, server_hostname=hostname) as tls:
                                if hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest().upper() != pin:
                                    raise ValueError("server pin mismatch")
                                tls.sendall(frame)
                                return tls.recv(128)
                    frame = b'{"operation":"preflight","revision":7,"digest":"' + b'A'*64 + b'"}\n'
                    for identity, pin, hostname in (("client","0"*64,"127.0.0.1"),
                            ("client",server_pin,"wrong.invalid"), (None,server_pin,"127.0.0.1")):
                        with self.assertRaises((ValueError, OSError, ssl.SSLError)):
                            response = exchange(identity, frame, pin, hostname)
                            if not response:
                                raise ValueError("no authenticated response")
                    try:
                        self.assertEqual(exchange("intruder",frame),b"")
                    except (OSError,ssl.SSLError):
                        pass
                    dispatch.assert_not_called()
                    self.assertEqual(exchange("client",b"A"*1025+b"\n"),b"refused-or-failed\n")
                    dispatch.assert_not_called()
                    self.assertEqual(exchange("client",frame),b"preflight-only\n")
                    dispatch.assert_called_once_with(frame)
                finally:
                    server.shutdown()
                    worker.join(4)
                self.assertFalse(worker.is_alive())


if __name__ == "__main__":
    unittest.main()
