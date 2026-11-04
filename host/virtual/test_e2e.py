"""Independent CTAP client -> Linux hidraw -> UHID -> real omk_core."""
import concurrent.futures
import json
import os
import pathlib
import secrets
import tempfile
import threading
import time
import unittest
import urllib.request
import urllib.error

from fido2.attestation import PackedAttestation
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.credman import CredentialManagement
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2
from fido2.hid import open_device
from fido2.webauthn import PublicKeyCredentialDescriptor

from service import Device, make_server

ROOT = pathlib.Path(__file__).resolve().parents[2]
RUNS = ROOT / "build/virtual-hid/runs"
RUNS.mkdir(parents=True, exist_ok=True)
RUN = pathlib.Path(tempfile.mkdtemp(prefix="run-", dir=RUNS))
RP = {"id": "virtual.example", "name": "Virtual test"}


class VirtualHidTests(unittest.TestCase):
    def setUp(self):
        self.device = Device(ROOT / "build/virtual-hid/linux/host/omk_virtual",
                             RUN / (self._testMethodName + ".flash"))
        self.addCleanup(self.device.stop)
        self.device.powercycle()
        self.server = make_server(self.device, ("127.0.0.1", 0), RUN / "official-results.json")
        self.thread = threading.Thread(
            target=lambda: self.server.serve_forever(poll_interval=0.05), daemon=True
        )
        self.thread.start()
        self.addCleanup(self.close_server)
        self.hid = None
        self.addCleanup(self.close_hid)
        self.connect()

    def close_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def close_hid(self):
        if self.hid is not None:
            self.hid.close()
            self.hid = None

    def connect(self):
        self.close_hid()
        paths = self.device.paths()
        self.assertEqual(len(paths), 1)
        self.hid = open_device(paths[0])
        self.ctap = Ctap2(self.hid)

    def rpc(self, path, body=None):
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.server.server_port}{path}",
            data=json.dumps(body or {}).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(request, timeout=12) as response:
            return json.load(response)

    def powercycle(self):
        self.close_hid()
        generation = self.device.generation
        self.rpc("/conformance/powercycle")
        self.assertEqual(self.device.generation, generation + 1)
        self.connect()

    def make(self, alg=-7, resident=False, **kwargs):
        client_hash = os.urandom(32)
        response = self.ctap.make_credential(
            client_hash, RP, {"id": os.urandom(16), "name": "synthetic-user"},
            [{"type": "public-key", "alg": alg}], options={"rk": resident}, **kwargs,
        )
        self.assertEqual(response.fmt, "packed")
        PackedAttestation().verify(response.att_stmt, response.auth_data, client_hash)
        return response.auth_data.credential_data

    def assert_credential(self, credential, discoverable=False, **kwargs):
        client_hash = os.urandom(32)
        allow = None if discoverable else [{"type": "public-key", "id": credential.credential_id}]
        response = self.ctap.get_assertion(RP["id"], client_hash, allow_list=allow, **kwargs)
        self.assertTrue(response.credential["id"] == credential.credential_id)
        credential.public_key.verify(bytes(response.auth_data) + client_hash, response.signature)
        self.assertTrue(response.auth_data.is_user_present())
        return response

    def expect_error(self, code, action):
        with self.assertRaises(CtapError) as raised:
            action()
        self.assertEqual(raised.exception.code, code)

    def test_info_and_fragmented_ping(self):
        info = self.ctap.get_info()
        self.assertIn("FIDO_2_3", info.versions)
        self.assertEqual(set(info.pin_uv_protocols), {1, 2})
        payload = os.urandom(1500)
        self.assertTrue(self.hid.ping(payload) == payload)

    def test_es256_and_eddsa_signatures(self):
        for alg in (-7, -8):
            with self.subTest(algorithm=alg):
                credential = self.make(alg)
                first = self.assert_credential(credential)
                second = self.assert_credential(credential)
                self.assertGreater(second.auth_data.counter, first.auth_data.counter)

    def test_resident_credential_persists(self):
        credential = self.make(resident=True)
        first = self.assert_credential(credential, discoverable=True)
        self.powercycle()
        second = self.assert_credential(credential, discoverable=True)
        self.assertGreater(second.auth_data.counter, first.auth_data.counter)

    def test_pin_protocols_and_change(self):
        for protocol in (PinProtocolV1(), PinProtocolV2()):
            with self.subTest(protocol=protocol.VERSION):
                self.powercycle()
                self.ctap.reset()
                pin = secrets.token_hex(4)
                client = ClientPin(self.ctap, protocol)
                client.set_pin(pin)
                challenge = os.urandom(32)
                token = client.get_pin_token(pin, ClientPin.PERMISSION.MAKE_CREDENTIAL, RP["id"])
                response = self.ctap.make_credential(
                    challenge, RP, {"id": os.urandom(16)}, [{"type": "public-key", "alg": -7}],
                    pin_uv_param=protocol.authenticate(token, challenge),
                    pin_uv_protocol=protocol.VERSION,
                )
                self.assertTrue(response.auth_data.is_user_verified())
                PackedAttestation().verify(response.att_stmt, response.auth_data, challenge)
                new_pin = secrets.token_hex(4)
                client.change_pin(pin, new_pin)
                self.powercycle()
                client = ClientPin(self.ctap, protocol)
                self.assertTrue(self.ctap.info.options["clientPin"])
                self.assertEqual(len(client.get_pin_token(new_pin)), 32)

    def test_pin_retry_persists(self):
        pin = secrets.token_hex(4)
        client = ClientPin(self.ctap, PinProtocolV2())
        client.set_pin(pin)
        self.expect_error(CtapError.ERR.PIN_INVALID,
                          lambda: client.get_pin_token(pin + "x"))
        self.assertEqual(client.get_pin_retries()[0], 7)
        self.powercycle()
        client = ClientPin(self.ctap, PinProtocolV2())
        self.assertEqual(client.get_pin_retries()[0], 7)
        client.get_pin_token(pin)
        self.assertEqual(client.get_pin_retries()[0], 8)

    def test_cancel_while_waiting_for_presence(self):
        self.rpc("/control/mode", {"auto_touch_ms": None})
        event = threading.Event()
        statuses = []
        def keepalive(status):
            statuses.append(status)
            event.set()
        self.expect_error(CtapError.ERR.KEEPALIVE_CANCEL,
                          lambda: self.make(event=event, on_keepalive=keepalive))
        self.assertIn(2, statuses)
        self.rpc("/control/mode", {"auto_touch_ms": 250})
        self.assert_credential(self.make())

    def test_official_userpresence_endpoint(self):
        self.rpc("/control/mode", {"auto_touch_ms": None})
        # A touch with no pending request must not approve the next command.
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self.rpc("/conformance/userpresence")
        self.assertEqual(raised.exception.code, 503)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            touches = []
            def keepalive(status):
                if status == 2 and not touches:
                    touches.append(pool.submit(self.rpc, "/conformance/userpresence"))
            self.ctap.selection(on_keepalive=keepalive)
            self.assertEqual(len(touches), 1)
            self.assertTrue(touches[0].result(timeout=3)["ok"])

    def test_reset_window_and_state(self):
        credential = self.make(resident=True)
        ClientPin(self.ctap).set_pin(secrets.token_hex(4))
        time.sleep(10.1)  # Exercise the real core's wall-clock window.
        self.expect_error(CtapError.ERR.NOT_ALLOWED, self.ctap.reset)
        self.powercycle()
        self.assertTrue(self.ctap.info.options["clientPin"])
        self.ctap.reset()
        self.assertFalse(self.ctap.get_info().options["clientPin"])
        self.expect_error(CtapError.ERR.NO_CREDENTIALS,
                          lambda: self.assert_credential(credential))

    def test_powercycle_invalidates_pin_token(self):
        credential = self.make()
        pin = secrets.token_hex(4)
        protocol = PinProtocolV2()
        client = ClientPin(self.ctap, protocol)
        client.set_pin(pin)
        token = client.get_pin_token(pin, ClientPin.PERMISSION.GET_ASSERTION, RP["id"])
        self.powercycle()
        challenge = os.urandom(32)
        self.expect_error(CtapError.ERR.PIN_AUTH_INVALID, lambda: self.ctap.get_assertion(
            RP["id"], challenge,
            allow_list=[{"type": "public-key", "id": credential.credential_id}],
            pin_uv_param=protocol.authenticate(token, challenge), pin_uv_protocol=2,
        ))
        token = ClientPin(self.ctap, protocol).get_pin_token(
            pin, ClientPin.PERMISSION.GET_ASSERTION, RP["id"])
        response = self.ctap.get_assertion(
            RP["id"], challenge,
            allow_list=[{"type": "public-key", "id": credential.credential_id}],
            pin_uv_param=protocol.authenticate(token, challenge), pin_uv_protocol=2,
        )
        self.assertTrue(response.auth_data.is_user_verified())
        credential.public_key.verify(bytes(response.auth_data) + challenge, response.signature)

    def test_credential_management(self):
        self.make(resident=True)
        self.make(resident=True)
        pin = secrets.token_hex(4)
        protocol = PinProtocolV2()
        client = ClientPin(self.ctap, protocol)
        client.set_pin(pin)
        token = client.get_pin_token(pin, ClientPin.PERMISSION.CREDENTIAL_MGMT)
        manager = CredentialManagement(self.ctap, protocol, token)
        rps = manager.enumerate_rps()
        self.assertEqual(len(rps), 1)
        credentials = manager.enumerate_creds(rps[0][4])
        self.assertEqual(len(credentials), 2)
        descriptor = credentials[0][7]
        self.assertEqual(descriptor["type"], "public-key")
        manager.delete_cred(PublicKeyCredentialDescriptor.from_dict(descriptor))
        self.assertEqual(len(manager.enumerate_creds(rps[0][4])), 1)


if __name__ == "__main__":
    started = time.monotonic()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(VirtualHidTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {"tests": result.testsRun, "failures": len(result.failures),
              "errors": len(result.errors), "seconds": round(time.monotonic() - started, 2)}
    (RUN / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print("Report:", RUN.relative_to(ROOT) / "result.json")
    raise SystemExit(0 if result.wasSuccessful() else 1)
