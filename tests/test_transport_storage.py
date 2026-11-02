import asyncio
import os
import socket
import struct

import pytest
from fido2.hid.base import parse_report_descriptor

from fido2_emulator.authenticator import Authenticator
from fido2_emulator.hid import HidDevice, TouchGate, packets
from fido2_emulator.storage import FileStore, MemoryStore
from fido2_emulator.usbip import CONFIG_DESCRIPTOR, DEVICE_DESCRIPTOR, REPORT_DESCRIPTOR


def test_os_enumeration_descriptors(rig):
    for value, expected, kind in [
        (0x0100, DEVICE_DESCRIPTOR, 0x80),
        (0x0200, CONFIG_DESCRIPTOR, 0x80),
        (0x2200, REPORT_DESCRIPTOR, 0x81),
    ]:
        setup = struct.pack("<BBHHH", kind, 6, value, 0, 255)
        assert rig.connection.transfer(1, 0, size=255, setup=setup) == expected
    assert len(CONFIG_DESCRIPTOR) == int.from_bytes(CONFIG_DESCRIPTOR[2:4], "little")
    assert parse_report_descriptor(REPORT_DESCRIPTOR) == (64, 64)


def test_second_import_rejected_and_devlist(rig):
    with socket.create_connection(("127.0.0.1", rig.port), 2) as sock:
        sock.sendall(struct.pack(">HHI32s", 0x0111, 0x8003, 0, b"1-1"))
        assert struct.unpack(">HHI", sock.recv(8)) == (0x0111, 3, 1)
    with socket.create_connection(("127.0.0.1", rig.port), 2) as sock:
        sock.sendall(struct.pack(">HHI", 0x0111, 0x8005, 0))
        assert struct.unpack(">HHII", sock.recv(12)) == (0x0111, 5, 0, 0)


def test_unlink_pending_read_has_no_submit_reply(rig):
    conn = rig.connection
    conn.sequence += 1
    pending = conn.sequence
    conn.sock.sendall(
        struct.pack(">IIIIIIiiii8s", 1, pending, 0x10001, 1, 1, 0, 64, 0, 0, 5, bytes(8))
    )
    conn.sequence += 1
    conn.sock.sendall(
        struct.pack(">IIIIII24s", 2, conn.sequence, 0x10001, 0, 0, pending, bytes(24))
    )
    raw = conn.read_exact(48)
    assert struct.unpack(">IIIIIi", raw[:24]) == (4, conn.sequence, 0, 0, 0, -104)
    assert rig.device.ping(b"still alive") == b"still alive"


def test_bad_sequence_and_channel_isolation():
    async def test():
        output = []
        hid = HidDevice(Authenticator(MemoryStore(), None), output.append)
        hid.channels = {1, 2}
        frames = list(packets(1, 1, bytes(100)))
        hid.feed(frames[0])
        hid.feed(list(packets(2, 1, b"foreign"))[0])
        assert output.pop()[7] == 6
        wrong = frames[1][:4] + b"\x01" + frames[1][5:]
        hid.feed(wrong)
        assert output.pop()[7] == 4
        hid.feed(list(packets(0, 1, b""))[0])
        assert output.pop()[7] == 11
        await hid.close()

    asyncio.run(test())


def test_touch_gate_does_not_bank_touches():
    async def test():
        gate = TouchGate()
        assert gate.touch() is False
        task = asyncio.create_task(gate.request("Register", "example.test"))
        await asyncio.sleep(0)
        assert not task.done()
        assert gate.touch() is True
        assert await task is True
        assert gate.pending is None
        assert gate.touch() is False

    asyncio.run(test())


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI integration")
def test_dpapi_persistence_and_tamper_rejection(tmp_path):
    path = tmp_path / "keys.dpapi"
    store = FileStore(path)
    store.data["credentials"] = [{"key": "private-secret", "rp": "example.test"}]
    store.save()
    assert b"private-secret" not in path.read_bytes()
    assert FileStore(path).data == store.data
    raw = bytearray(path.read_bytes())
    raw[-1] ^= 1
    path.write_bytes(raw)
    with pytest.raises(OSError):
        FileStore(path)
