"""CTAP 2.0, ES256, resident credentials, and ClientPIN protocol 1."""

import asyncio
import hashlib
import hmac
import logging
import secrets
import time
from collections import deque
from uuid import UUID

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fido2 import cbor

from .storage import MemoryStore

LOG = logging.getLogger(__name__)
AAGUID = UUID("fe8a20d7-1cd5-4c0b-b578-19ce8c695247").bytes
MAX_MESSAGE = 7609


class CtapFailure(Exception):
    def __init__(self, code: int):
        self.code = code


def require(condition, code=0x02):
    if not condition:
        raise CtapFailure(code)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def mac(key: bytes, data: bytes) -> bytes:
    return hmac.digest(key, data, "sha256")[:16]


def aes(key: bytes, data: bytes, decrypt=False) -> bytes:
    require(isinstance(data, bytes) and len(data) > 0 and len(data) % 16 == 0)
    cipher = Cipher(algorithms.AES(key), modes.CBC(bytes(16)))
    operation = cipher.decryptor() if decrypt else cipher.encryptor()
    return operation.update(data) + operation.finalize()


def cose_key(key, algorithm=-7):
    numbers = key.public_key().public_numbers()
    return {
        1: 2,
        3: algorithm,
        -1: 1,
        -2: numbers.x.to_bytes(32, "big"),
        -3: numbers.y.to_bytes(32, "big"),
    }


def client_hash(params, number):
    value = params.get(number)
    require(isinstance(value, bytes) and len(value) == 32)
    return value


def credential_list(value):
    require(isinstance(value, list) and len(value) <= 64, 0x15)
    for item in value:
        require(isinstance(item, dict) and isinstance(item.get("id"), bytes))
        require(isinstance(item.get("type"), str))
    return value


def options(params, number, supported):
    result = params.get(number, {})
    require(isinstance(result, dict))
    for key, value in result.items():
        require(isinstance(value, bool), 0x11)
        require(key in supported or value is False, 0x2B)
    return result


class Authenticator:
    def __init__(self, store: MemoryStore, presence, *, touch_timeout=30):
        self.store = store
        self.presence = presence
        self.touch_timeout = touch_timeout
        self.power_on()

    def power_on(self):
        self.agreement = ec.generate_private_key(ec.SECP256R1())
        self.token = secrets.token_bytes(32)
        self.token_expiry = 0.0
        self.consecutive_failures = 0
        self.assertions = deque()
        self.assertion_expiry = 0.0

    def info(self):
        return {
            1: ["FIDO_2_0"],
            3: AAGUID,
            4: {
                "rk": True,
                "up": True,
                "plat": False,
                "clientPin": self.store.data["pin_hash"] is not None,
            },
            5: MAX_MESSAGE,
            6: [1],
            7: 64,
            8: 64,
            9: ["usb"],
            10: [{"type": "public-key", "alg": -7}],
        }

    async def handle(self, message: bytes) -> bytes:
        try:
            require(0 < len(message) <= MAX_MESSAGE, 0x03)
            command = message[0]
            try:
                params = cbor.decode(message[1:]) if len(message) > 1 else {}
            except (ValueError, TypeError, IndexError, KeyError, RecursionError):
                raise CtapFailure(0x12) from None
            require(isinstance(params, dict), 0x11)
            if command != 0x08:
                self.assertions.clear()
            if command == 0x04:
                result = self.info()
            elif command == 0x06:
                result = self.client_pin(params)
            elif command == 0x01:
                result = await self.make_credential(params)
            elif command == 0x02:
                result = await self.get_assertion(params)
            elif command == 0x08:
                require(self.assertions and time.monotonic() < self.assertion_expiry, 0x30)
                result = self.assertions.popleft()
            else:
                # Reset and optional commands are deliberately unavailable over CTAP.
                raise CtapFailure(0x01)
            return b"\x00" + (cbor.encode(result) if result else b"")
        except CtapFailure as error:
            return bytes([error.code])
        except asyncio.CancelledError:
            raise
        except (ValueError, TypeError, KeyError, OverflowError):
            return b"\x02"
        except Exception:
            LOG.exception("Authenticator operation failed")
            return b"\x7f"

    async def touch(self, operation, rp_id):
        try:
            accepted = await asyncio.wait_for(
                self.presence(operation, rp_id), timeout=self.touch_timeout
            )
        except TimeoutError:
            raise CtapFailure(0x2F) from None
        require(accepted, 0x27)

    def verify_pin(self, params, auth_number, protocol_number, digest):
        authorization = params.get(auth_number)
        if authorization is None:
            return False
        if authorization == b"":
            raise CtapFailure(0x35 if self.store.data["pin_hash"] is None else 0x31)
        require(params.get(protocol_number) == 1)
        require(self.store.data["pin_hash"] is not None, 0x35)
        require(time.monotonic() < self.token_expiry, 0x38)
        require(
            isinstance(authorization, bytes)
            and hmac.compare_digest(authorization, mac(self.token, digest)),
            0x33,
        )
        return True

    async def make_credential(self, params):
        digest = client_hash(params, 1)
        rp = params.get(2)
        user = params.get(3)
        require(isinstance(rp, dict) and isinstance(rp.get("id"), str), 0x14)
        require(0 < len(rp["id"].encode()) <= 253)
        require(isinstance(user, dict) and isinstance(user.get("id"), bytes), 0x14)
        require(0 < len(user["id"]) <= 64)
        for field in ("name", "displayName"):
            require(field not in user or isinstance(user[field], str))
        algorithms_requested = params.get(4)
        require(isinstance(algorithms_requested, list), 0x14)
        require(
            any(
                isinstance(a, dict) and a.get("alg") == -7 and a.get("type") == "public-key"
                for a in algorithms_requested
            ),
            0x26,
        )
        opts = options(params, 7, {"rk", "uv"})
        verified = self.verify_pin(params, 8, 9, digest)
        require(not opts.get("uv") or verified, 0x2B)
        require(self.store.data["pin_hash"] is None or verified, 0x36)
        excluded = credential_list(params.get(5, []))
        await self.touch("Register", rp["id"])
        for item in excluded:
            if any(
                c["id"] == item["id"].hex() and c["rp"] == rp["id"]
                for c in self.store.data["credentials"]
            ):
                raise CtapFailure(0x19)
        require(len(self.store.data["credentials"]) < 256, 0x28)
        key = ec.generate_private_key(ec.SECP256R1())
        identifier = secrets.token_bytes(32)
        resident = opts.get("rk", False)
        if resident:
            # Re-registering the same resident RP/user replaces its old credential.
            self.store.data["credentials"] = [
                c
                for c in self.store.data["credentials"]
                if not (c["rp"] == rp["id"] and c["user_id"] == user["id"].hex() and c["resident"])
            ]
        self.store.data["credentials"].append(
            {
                "id": identifier.hex(),
                "rp": rp["id"],
                "user_id": user["id"].hex(),
                "name": user.get("name", ""),
                "displayName": user.get("displayName", ""),
                "resident": resident,
                "key": key.private_bytes(
                    serialization.Encoding.DER,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ).hex(),
            }
        )
        self.store.save()
        auth_data = (
            sha256(rp["id"].encode())
            + bytes([0x41 | (4 if verified else 0)])
            + self.store.data["counter"].to_bytes(4, "big")
            + AAGUID
            + len(identifier).to_bytes(2, "big")
            + identifier
            + cbor.encode(cose_key(key))
        )
        return {1: "none", 2: auth_data, 3: {}}

    async def get_assertion(self, params):
        rp_id = params.get(1)
        require(isinstance(rp_id, str) and 0 < len(rp_id.encode()) <= 253, 0x14)
        digest = client_hash(params, 2)
        opts = options(params, 5, {"up", "uv"})
        verified = self.verify_pin(params, 6, 7, digest)
        require(not opts.get("uv") or verified, 0x2B)
        allowed = credential_list(params[3]) if 3 in params else None
        matches = [
            c
            for c in self.store.data["credentials"]
            if c["rp"] == rp_id
            and (
                any(a["type"] == "public-key" and a["id"].hex() == c["id"] for a in allowed)
                if allowed
                else c["resident"]
            )
        ]
        require(matches, 0x2E)
        present = opts.get("up", True)
        if present:
            await self.touch("Authenticate", rp_id)
        responses = []
        for cred in matches:
            self.store.data["counter"] += 1
            require(self.store.data["counter"] <= 0xFFFFFFFF, 0x7F)
            flags = (1 if present else 0) | (4 if verified else 0)
            auth_data = (
                sha256(rp_id.encode())
                + bytes([flags])
                + self.store.data["counter"].to_bytes(4, "big")
            )
            key = serialization.load_der_private_key(bytes.fromhex(cred["key"]), None)
            response = {
                1: {"type": "public-key", "id": bytes.fromhex(cred["id"])},
                2: auth_data,
                3: key.sign(auth_data + digest, ec.ECDSA(hashes.SHA256())),
            }
            if cred["resident"]:
                response[4] = {"id": bytes.fromhex(cred["user_id"])}
                if verified:
                    response[4].update(name=cred["name"], displayName=cred["displayName"])
            responses.append(response)
        self.store.save()
        if len(responses) > 1:
            responses[0][5] = len(responses)
        self.assertions = deque(responses[1:])
        self.assertion_expiry = time.monotonic() + 30
        return responses[0]

    def shared_secret(self, peer):
        require(
            isinstance(peer, dict) and peer.get(1) == 2 and peer.get(3) == -25 and peer.get(-1) == 1
        )
        require(isinstance(peer.get(-2), bytes) and len(peer[-2]) == 32)
        require(isinstance(peer.get(-3), bytes) and len(peer[-3]) == 32)
        public = ec.EllipticCurvePublicNumbers(
            int.from_bytes(peer[-2], "big"), int.from_bytes(peer[-3], "big"), ec.SECP256R1()
        ).public_key()
        return sha256(self.agreement.exchange(ec.ECDH(), public))

    def check_pin_hash(self, shared, encrypted):
        require(self.store.data["pin_hash"] is not None, 0x35)
        require(self.store.data["retries"] > 0, 0x32)
        require(self.consecutive_failures < 3, 0x34)
        require(isinstance(encrypted, bytes) and len(encrypted) == 16)
        value = aes(shared, encrypted, decrypt=True)
        self.store.data["retries"] -= 1
        self.store.save()
        if not hmac.compare_digest(value.hex(), self.store.data["pin_hash"]):
            self.agreement = ec.generate_private_key(ec.SECP256R1())
            self.consecutive_failures += 1
            self.token_expiry = 0
            require(self.store.data["retries"] > 0, 0x32)
            require(self.consecutive_failures < 3, 0x34)
            raise CtapFailure(0x31)
        self.store.data["retries"] = 8
        self.consecutive_failures = 0
        self.store.save()

    def client_pin(self, params):
        require(params.get(1) == 1)
        command = params.get(2)
        if command == 1:
            return {3: self.store.data["retries"]}
        if command == 2:
            return {1: cose_key(self.agreement, -25)}
        require(command in (3, 4, 5), 0x01)
        shared = self.shared_secret(params.get(3))
        if command == 5:
            self.check_pin_hash(shared, params.get(6))
            self.token_expiry = time.monotonic() + 30
            return {2: aes(shared, self.token)}
        require(command != 3 or self.store.data["pin_hash"] is None, 0x30)
        encrypted = params.get(5)
        require(isinstance(encrypted, bytes) and len(encrypted) == 64)
        auth_message = encrypted
        if command == 4:
            require(isinstance(params.get(6), bytes) and len(params[6]) == 16)
            auth_message += params[6]
        require(
            isinstance(params.get(4), bytes)
            and hmac.compare_digest(params[4], mac(shared, auth_message)),
            0x33,
        )
        if command == 4:
            self.check_pin_hash(shared, params[6])
        padded_pin = aes(shared, encrypted, decrypt=True)
        pin = padded_pin.rstrip(b"\0")
        require(b"\0" not in pin and 4 <= len(pin.decode("utf-8")) and len(pin) <= 63, 0x37)
        self.store.data["pin_hash"] = sha256(pin)[:16].hex()
        self.store.data["retries"] = 8
        self.token = secrets.token_bytes(32)
        self.token_expiry = 0
        self.store.save()
        return {}
