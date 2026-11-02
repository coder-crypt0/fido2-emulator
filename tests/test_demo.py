import http.client
import json
import threading
from http.server import HTTPServer

from fido2.ctap2 import Ctap2
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import AttestationObject, CollectedClientData

from fido2_emulator.demo import make_handler


def test_browser_demo_actual_http_registration_login_origin_and_replay(rig):
    server = HTTPServer(("127.0.0.1", 0), make_handler())
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    client = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    headers = {"Host": "localhost:8765"}
    try:
        client.request("GET", "/", headers=headers)
        response = client.getresponse()
        assert response.status == 200
        assert b"navigator.credentials" in response.read()
        headers["Cookie"] = response.getheader("Set-Cookie").split(";", 1)[0]

        def post(path, data):
            client.request("POST", path, json.dumps(data), headers)
            response = client.getresponse()
            body = json.loads(response.read())
            return response.status, body

        assert post("/register/begin", {})[0] == 403
        headers["Origin"] = "http://localhost:8765"
        status, creation = post("/register/begin", {})
        assert status == 200
        params = creation["publicKey"]
        data = CollectedClientData.create(
            "webauthn.create", websafe_decode(params["challenge"]), "http://localhost:8765"
        )
        ctap = Ctap2(rig.device)
        attestation = ctap.make_credential(
            data.hash,
            params["rp"],
            {**params["user"], "id": websafe_decode(params["user"]["id"])},
            params["pubKeyCredParams"],
        )
        cred = attestation.auth_data.credential_data
        response = {
            "id": websafe_encode(cred.credential_id),
            "rawId": websafe_encode(cred.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": websafe_encode(data),
                "attestationObject": websafe_encode(
                    AttestationObject.create(
                        attestation.fmt, attestation.auth_data, attestation.att_stmt
                    )
                ),
            },
        }
        assert post("/register/complete", response)[0] == 200
        assert post("/register/complete", response)[0] == 400
        status, request = post("/login/begin", {})
        assert status == 200
        data = CollectedClientData.create(
            "webauthn.get",
            websafe_decode(request["publicKey"]["challenge"]),
            "http://localhost:8765",
        )
        assertion = ctap.get_assertion(
            "localhost", data.hash, [{"type": "public-key", "id": cred.credential_id}]
        )
        response = {
            "id": websafe_encode(cred.credential_id),
            "rawId": websafe_encode(cred.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": websafe_encode(data),
                "authenticatorData": websafe_encode(assertion.auth_data),
                "signature": websafe_encode(assertion.signature),
            },
        }
        status, body = post("/login/complete", response)
        assert status == 200
        assert "Sign-in verified" in body["message"]
        assert post("/login/complete", response)[0] == 400
    finally:
        client.close()
        server.shutdown()
        server.server_close()
        worker.join(3)
