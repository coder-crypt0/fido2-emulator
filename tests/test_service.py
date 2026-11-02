import concurrent.futures
import json
import os
import socket
import subprocess
import sys
import time

import pytest
from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice
from fido2.hid.base import HidDescriptor
from usbip_client import HostConnection

from fido2_emulator.controller import Emulator
from fido2_emulator.service import read_runtime
from fido2_emulator.storage import FileStore
from fido2_emulator.usbip import PID, VID


def free_ports():
    with socket.socket() as first, socket.socket() as second:
        first.bind(("127.0.0.1", 0))
        second.bind(("127.0.0.1", 0))
        return first.getsockname()[1], second.getsockname()[1]


@pytest.mark.skipif(os.name != "nt", reason="Daemon requires Windows DPAPI")
def test_real_daemon_requires_authenticated_touch_and_persists_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("FIDO2_EMULATOR_HOME", str(tmp_path))
    usb_port, control_port = free_ports()
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "fido2_emulator",
            "serve",
            "--usb-port",
            str(usb_port),
            "--control-port",
            str(control_port),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    emulator = Emulator()
    connection = None
    try:
        for _ in range(100):
            if emulator.status()["running"]:
                break
            time.sleep(0.05)
        assert emulator.status()["running"]
        assert emulator.touch() is False
        runtime = read_runtime()
        assert runtime["token"].encode() not in (tmp_path / "runtime.dpapi").read_bytes()
        connection = HostConnection(usb_port)
        device = CtapHidDevice(
            HidDescriptor("local-test", VID, PID, 64, 64, None, None), connection
        )
        ctap = Ctap2(device)
        with concurrent.futures.ThreadPoolExecutor() as pool:
            future = pool.submit(
                ctap.make_credential,
                bytes(32),
                {"id": "example.test", "name": "Test"},
                {"id": b"lab-user", "name": "lab-user"},
                [{"type": "public-key", "alg": -7}],
            )
            for _ in range(100):
                if emulator.status().get("pending"):
                    break
                time.sleep(0.01)
            assert emulator.status()["pending"]["rp"] == "example.test"
            with socket.create_connection(("127.0.0.1", control_port), timeout=2) as unauthorized:
                unauthorized.sendall(
                    json.dumps({"token": "0" * 64, "command": "touch"}).encode() + b"\n"
                )
                assert unauthorized.recv(4096) == b""
            assert not future.done()
            assert emulator.status()["credentials"] == 0
            assert emulator.touch() is True
            assert future.result(5).auth_data.is_user_present()
        connection.close()
        connection = None
        emulator.request("stop")
        process.wait(5)
        assert process.returncode == 0
        assert not (tmp_path / "runtime.dpapi").exists()
        assert len(FileStore(tmp_path / "credentials.dpapi").data["credentials"]) == 1
    finally:
        if connection:
            connection.close()
        if process.poll() is None:
            process.terminate()
            process.wait(5)
