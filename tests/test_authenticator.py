import asyncio
import os
import threading

import pytest
from cryptography.exceptions import InvalidSignature
from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin, PinProtocolV1
from fido2.hid import CTAPHID
from fido2.server import Fido2Server
from fido2.utils import websafe_encode
from fido2.webauthn import AttestationObject, CollectedClientData
from usbip_client import TestRig

from fido2_emulator.authenticator import Authenticator
from fido2_emulator.storage import MemoryStore

RP = {"id": "example.test", "name": "Local Test"}
USER = {"id": b"lab-user", "name": "lab-user", "displayName": "Lab User"}
ALGORITHMS = [{"type": "public-key", "alg": -7}]


def register(ctap, **kwargs):
    return ctap.make_credential(os.urandom(32), RP, USER, ALGORITHMS, **kwargs)


def test_real_yubico_client_registration_signature_and_counter(rig):
    ctap = Ctap2(rig.device)
    assert ctap.info.versions == ["FIDO_2_0"]
    assert ctap.info.options["plat"] is False
    registration = register(ctap)
    cred = registration.auth_data.credential_data
    allowed = [{"id": cred.credential_id, "type": "public-key"}]
    digest = os.urandom(32)
    first = ctap.get_assertion(RP["id"], digest, allowed)
    cred.public_key.verify(first.auth_data + digest, first.signature)
    second = ctap.get_assertion(RP["id"], digest, allowed)
    assert second.auth_data.counter > first.auth_data.counter
    assert first.auth_data.is_user_present()
    assert not first.auth_data.is_user_verified()
    with pytest.raises(InvalidSignature):
        cred.public_key.verify(first.auth_data + os.urandom(32), first.signature)
    with pytest.raises(CtapError) as error:
        ctap.get_assertion("other.test", digest, allowed)
    assert error.value.code == CtapError.ERR.NO_CREDENTIALS


def test_full_webauthn_relying_party_verifies_over_usbip(rig):
    ctap = Ctap2(rig.device)
    server = Fido2Server(RP)
    creation, registration_state = server.register_begin(USER)
    client = CollectedClientData.create(
        "webauthn.create", creation.public_key.challenge, "https://example.test"
    )
    result = ctap.make_credential(client.hash, RP, USER, ALGORITHMS)
    attestation = AttestationObject.create(result.fmt, result.auth_data, result.att_stmt)
    cred = result.auth_data.credential_data
    registration = {
        "id": websafe_encode(cred.credential_id),
        "rawId": websafe_encode(cred.credential_id),
        "type": "public-key",
        "response": {"clientDataJSON": client, "attestationObject": attestation},
    }
    auth_data = server.register_complete(registration_state, registration)
    request, state = server.authenticate_begin([auth_data.credential_data])
    client = CollectedClientData.create(
        "webauthn.get", request.public_key.challenge, "https://example.test"
    )
    assertion = ctap.get_assertion(
        RP["id"], client.hash, [{"type": "public-key", "id": cred.credential_id}]
    )
    response = {
        "id": websafe_encode(cred.credential_id),
        "rawId": websafe_encode(cred.credential_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": client,
            "authenticatorData": assertion.auth_data,
            "signature": assertion.signature,
        },
    }
    verified = server.authenticate_complete(state, [auth_data.credential_data], response)
    assert verified.credential_id == cred.credential_id


def test_resident_credentials_and_next_assertion(rig):
    ctap = Ctap2(rig.device)
    for identifier in (b"lab-a", b"lab-b"):
        ctap.make_credential(
            os.urandom(32), RP, {**USER, "id": identifier}, ALGORITHMS, options={"rk": True}
        )
    results = ctap.get_assertions(RP["id"], os.urandom(32))
    assert len(results) == 2
    assert {a.user["id"] for a in results} == {b"lab-a", b"lab-b"}
    assert all("name" not in a.user for a in results)
    with pytest.raises(CtapError):
        ctap.get_next_assertion()


def test_excluded_and_unknown_credentials(rig):
    ctap = Ctap2(rig.device)
    cred = register(ctap).auth_data.credential_data
    with pytest.raises(CtapError) as error:
        register(ctap, exclude_list=[{"id": cred.credential_id, "type": "public-key"}])
    assert error.value.code == CtapError.ERR.CREDENTIAL_EXCLUDED
    with pytest.raises(CtapError):
        ctap.get_assertion(RP["id"], os.urandom(32), [{"id": os.urandom(32), "type": "public-key"}])


def test_pin_exchange_uv_flags_and_change(rig):
    ctap = Ctap2(rig.device)
    pin = ClientPin(ctap, PinProtocolV1())
    pin.set_pin("123456")
    with pytest.raises(CtapError) as error:
        register(ctap)
    assert error.value.code == CtapError.ERR.PUAT_REQUIRED
    token = pin.get_pin_token("123456")
    digest = os.urandom(32)
    registration = ctap.make_credential(
        digest,
        RP,
        USER,
        ALGORITHMS,
        options={"rk": True},
        pin_uv_param=PinProtocolV1().authenticate(token, digest),
        pin_uv_protocol=1,
    )
    assert registration.auth_data.is_user_verified()
    digest = os.urandom(32)
    result = ctap.get_assertion(
        RP["id"],
        digest,
        options={"uv": True},
        pin_uv_param=PinProtocolV1().authenticate(token, digest),
        pin_uv_protocol=1,
    )
    assert result.auth_data.is_user_verified()
    pin.change_pin("123456", "654321")
    assert len(pin.get_pin_token("654321")) == 32


def test_pin_lockout_and_power_cycle(rig):
    pin = ClientPin(Ctap2(rig.device), PinProtocolV1())
    pin.set_pin("123456")
    for attempt in range(3):
        with pytest.raises(CtapError) as error:
            pin.get_pin_token("999999")
    assert error.value.code == CtapError.ERR.PIN_AUTH_BLOCKED
    assert rig.store.data["retries"] == 5
    rig.loop.call_soon_threadsafe(rig.authenticator.power_on)
    assert len(pin.get_pin_token("123456")) == 32
    assert rig.store.data["retries"] == 8


def test_hid_large_ping_and_malformed_cbor(rig):
    data = os.urandom(7609)
    assert rig.device.call(CTAPHID.PING, data) == data
    assert rig.device.call(CTAPHID.CBOR, b"\x01\xa1") == b"\x12"
    assert rig.device.call(CTAPHID.CBOR, b"\x01" + cbor.encode([])) == b"\x11"
    assert rig.device.call(CTAPHID.CBOR, b"\x55") == b"\x01"


def test_touch_cancellation_over_real_hid_client():
    async def pending(operation, rp):
        await asyncio.Event().wait()

    rig = TestRig(pending)
    try:
        event = threading.Event()
        statuses = []

        def keepalive(status):
            statuses.append(status)
            event.set()

        with pytest.raises(CtapError) as error:
            register(Ctap2(rig.device), event=event, on_keepalive=keepalive)
        assert error.value.code == CtapError.ERR.KEEPALIVE_CANCEL
        assert statuses
        assert not rig.store.data["credentials"]
    finally:
        rig.close()


def test_touch_timeout_never_creates_credential():
    async def pending(operation, rp):
        await asyncio.Event().wait()

    auth = Authenticator(MemoryStore(), pending, touch_timeout=0.01)
    request = b"\x01" + cbor.encode({1: bytes(32), 2: RP, 3: USER, 4: ALGORITHMS})
    assert asyncio.run(auth.handle(request)) == b"\x2f"
    assert auth.store.data["credentials"] == []
