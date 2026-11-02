"""Independent USB/IP host adapter for Yubico's real CTAPHID client."""

import asyncio
import socket
import struct
import threading

from fido2.hid import CtapHidDevice
from fido2.hid.base import CtapHidConnection, HidDescriptor

from fido2_emulator.authenticator import Authenticator
from fido2_emulator.hid import TouchGate
from fido2_emulator.storage import MemoryStore
from fido2_emulator.usbip import PID, VID, UsbIpServer


class HostConnection(CtapHidConnection):
    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), 3)
        self.sock.settimeout(5)
        self.sequence = 0
        self.sock.sendall(struct.pack(">HHI32s", 0x0111, 0x8003, 0, b"1-1"))
        version, command, status = struct.unpack(">HHI", self.read_exact(8))
        assert (version, command, status) == (0x0111, 3, 0)
        assert len(self.read_exact(312)) == 312

    def read_exact(self, length):
        data = b""
        while len(data) < length:
            chunk = self.sock.recv(length - len(data))
            if not chunk:
                raise EOFError("USB/IP server disconnected")
            data += chunk
        return data

    def transfer(self, direction, endpoint, data=b"", size=64, setup=bytes(8)):
        self.sequence += 1
        length = size if direction else len(data)
        self.sock.sendall(
            struct.pack(
                ">IIIIIIiiii8s",
                1,
                self.sequence,
                0x10001,
                direction,
                endpoint,
                0,
                length,
                0,
                0,
                5,
                setup,
            )
            + (b"" if direction else data)
        )
        raw = self.read_exact(48)
        command, seq, device, response_dir, response_ep = struct.unpack(">IIIII", raw[:20])
        status, actual = struct.unpack(">ii", raw[20:28])
        assert (command, seq, device, response_dir, response_ep) == (3, self.sequence, 0, 0, 0)
        assert status == 0, status
        return self.read_exact(actual) if direction else b""

    def write_packet(self, data):
        self.transfer(0, 1, data)

    def read_packet(self):
        return self.transfer(1, 1)

    def close(self):
        self.sock.close()


class TestRig:
    __test__ = False

    def __init__(self, presence=None):
        self.loop = asyncio.new_event_loop()
        self.store = MemoryStore()
        self.gate = TouchGate()

        async def accept_presence(operation, rp):
            return True

        self.authenticator = Authenticator(self.store, presence or accept_presence)
        self.usb = UsbIpServer(self.authenticator, self.gate)
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()

        async def start():
            self.server = await asyncio.start_server(self.usb.accept, "127.0.0.1", 0)
            self.port = self.server.sockets[0].getsockname()[1]

        asyncio.run_coroutine_threadsafe(start(), self.loop).result(5)
        self.connection = HostConnection(self.port)
        descriptor = HidDescriptor("usbip-test", VID, PID, 64, 64, "Development Key", "test")
        self.device = CtapHidDevice(descriptor, self.connection)

    def close(self):
        self.connection.close()

        async def stop():
            self.usb.disconnect()
            self.server.close()
            await self.server.wait_closed()
            for _ in range(100):
                if self.usb.connection is None:
                    break
                await asyncio.sleep(0.01)

        asyncio.run_coroutine_threadsafe(stop(), self.loop).result(5)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        self.loop.close()
