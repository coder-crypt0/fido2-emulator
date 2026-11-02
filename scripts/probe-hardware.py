"""Exercise only this project's virtual key through the actual Windows HID stack.

Run in an Administrator terminal after plugging in the key. Approve each of the
two pending touches in the panel, or with the `touch` CLI command. No test traffic
leaves this computer. One persistent development credential is created.
"""

import argparse
import json
import secrets
import time

from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice

from fido2_emulator.controller import Emulator
from fido2_emulator.usbip import PID, VID

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "--auto-touch", action="store_true", help="Approve only this probe's randomly named local RP"
)
parser.add_argument("--replug", action="store_true", help="Verify credentials survive replug")
args = parser.parse_args()
emulator = Emulator()
rp_id = "probe-" + secrets.token_hex(8) + ".example.test"


def approve_probe(status):
    pending = emulator.status().get("pending")
    if args.auto_touch and pending and pending["rp"] == rp_id:
        emulator.touch()


def find_devices():
    return [
        item
        for item in CtapHidDevice.list_devices()
        if item.descriptor.vid == VID and item.descriptor.pid == PID
    ]


devices = find_devices()
if not devices:
    raise SystemExit(
        "Virtual key not found. Plug it in; Windows HID probing may require Administrator."
    )
device = devices[0]
try:
    ctap = Ctap2(device)
    print(
        "Actual Windows HID getInfo:",
        json.dumps({"versions": ctap.info.versions, "options": ctap.info.options}),
    )
    if ctap.info.options.get("clientPin"):
        raise SystemExit(
            "PIN already set: use the browser demo for PIN-based hardware verification."
        )
    registration = ctap.make_credential(
        secrets.token_bytes(32),
        {"id": rp_id, "name": "Local HID Probe"},
        {"id": b"lab-user", "name": "lab-user"},
        [{"type": "public-key", "alg": -7}],
        on_keepalive=approve_probe,
    )
    cred = registration.auth_data.credential_data
    if args.replug:
        for item in devices:
            item.close()
        devices = []
        emulator.unplug()
        time.sleep(0.5)
        emulator.plug()
        for _ in range(50):
            devices = find_devices()
            if devices:
                break
            time.sleep(0.1)
        if not devices:
            raise RuntimeError("Virtual key not found after replug")
        ctap = Ctap2(devices[0])
    digest = secrets.token_bytes(32)
    assertion = ctap.get_assertion(
        rp_id,
        digest,
        [{"type": "public-key", "id": cred.credential_id}],
        on_keepalive=approve_probe,
    )
    cred.public_key.verify(assertion.auth_data + digest, assertion.signature)
    print("PASS: Windows HID enumeration, CTAP2 registration, and assertion signature verified.")
    if args.replug:
        print("PASS: Credential survived Python-controlled unplug/replug.")
finally:
    for item in devices:
        item.close()
