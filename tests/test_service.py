import asyncio
import concurrent.futures
import json
import os
import socket
import subprocess
import sys
import time
from contextlib import closing, nullcontext

import pytest
from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice
from fido2.hid.base import HidDescriptor
from usbip_client import HostConnection

from fido2_emulator.controller import Emulator
from fido2_emulator.service import read_runtime, run
from fido2_emulator.storage import VAULT_NAME, FileStore, PortableStore
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


@pytest.mark.skipif(os.name != "nt", reason="Daemon requires Windows DPAPI")
def test_usb_vault_reopens_and_locks_on_removal(tmp_path, monkeypatch):
    class Drive:
        letter = "E:"
        present = True
        root = tmp_path / "usb"

        def check(self):
            if not self.present:
                raise OSError("Drive removed")

        def lock(self):
            return nullcontext()

    host = tmp_path / "host"
    monkeypatch.setenv("FIDO2_EMULATOR_HOME", str(host))
    drive = Drive()
    drive.root.mkdir()
    passphrase = "vault test passphrase"
    PortableStore.initialize(drive, passphrase)
    emulator = Emulator()

    def wait_for_touch():
        for _ in range(150):
            if emulator.status().get("pending"):
                return
            time.sleep(0.01)
        pytest.fail("No touch was requested")

    def use_key(port, registered=None):
        with closing(HostConnection(port)) as connection:
            ctap = Ctap2(
                CtapHidDevice(HidDescriptor("usb-test", VID, PID, 64, 64, None, None), connection)
            )
            with concurrent.futures.ThreadPoolExecutor() as pool:
                if registered is None:
                    future = pool.submit(
                        ctap.make_credential,
                        bytes(32),
                        {"id": "example.test", "name": "Test"},
                        {"id": b"portable-test-user", "name": "portable-test-user"},
                        [{"type": "public-key", "alg": -7}],
                    )
                    wait_for_touch()
                    assert emulator.touch()
                    return future.result(3).auth_data.credential_data

                digest = os.urandom(32)
                allowed = [{"id": registered.credential_id, "type": "public-key"}]
                future = pool.submit(ctap.get_assertion, "example.test", digest, allowed)
                wait_for_touch()
                assert emulator.touch()
                assertion = future.result(3)
                registered.public_key.verify(assertion.auth_data + digest, assertion.signature)

                pending = pool.submit(ctap.get_assertion, "example.test", digest, allowed)
                wait_for_touch()
                drive.present = False
                with pytest.raises((EOFError, ConnectionError)):
                    pending.result(3)

    async def run_session(registered=None):
        usb_port, control_port = free_ports()
        task = asyncio.create_task(
            run(usb_port, control_port, usb_drive=drive, passphrase=passphrase)
        )
        try:
            async with asyncio.timeout(5):
                while not (host / "runtime.dpapi").exists():
                    if task.done():
                        await task
                    await asyncio.sleep(0.01)
            assert (await asyncio.to_thread(emulator.status))["usb_drive"] == "E:"
            return await asyncio.to_thread(use_key, usb_port, registered)
        finally:
            if drive.present and not task.done():
                await asyncio.to_thread(emulator.unplug)
            await asyncio.wait_for(task, 3)

    async def exercise():
        credential = await run_session()
        assert not (host / "runtime.dpapi").exists()
        await run_session(credential)

    asyncio.run(exercise())
    assert not (host / "runtime.dpapi").exists()
    assert not (host / "credentials.dpapi").exists()
    assert b"portable-test-user" not in (drive.root / VAULT_NAME).read_bytes()
    drive.present = True
    assert PortableStore(drive, passphrase).data["counter"] == 1
