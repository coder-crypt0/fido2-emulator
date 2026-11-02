"""Loopback-only USB/IP server, USB enumeration, and HID interrupt endpoints."""

import asyncio
import logging
import struct
from collections import deque

from .hid import HidDevice

LOG = logging.getLogger(__name__)
BUS_ID = "1-1"
VID, PID = 0x1209, 0xF1D0  # Development identifiers; not an allocated production PID.
VERSION = 0x0111

REPORT_DESCRIPTOR = bytes.fromhex(
    "06d0f1 0901 a101 0920 1500 26ff00 7508 9540 8102 0921 1500 26ff00 7508 9540 9102 c0"
)
HID_DESCRIPTOR = struct.pack("<BBHBBBH", 9, 0x21, 0x0111, 0, 1, 0x22, len(REPORT_DESCRIPTOR))
DEVICE_DESCRIPTOR = struct.pack(
    "<BBHBBBBHHHBBBB", 18, 1, 0x0200, 0, 0, 0, 64, VID, PID, 0x0100, 1, 2, 3, 1
)
CONFIG_DESCRIPTOR = (
    struct.pack("<BBHBBBBB", 9, 2, 41, 1, 1, 0, 0x80, 50)
    + bytes([9, 4, 0, 0, 2, 3, 0, 0, 0])
    + HID_DESCRIPTOR
    + struct.pack("<BBBBHB", 7, 5, 0x81, 3, 64, 5)
    + struct.pack("<BBBBHB", 7, 5, 0x01, 3, 64, 5)
)


def device_record():
    return struct.pack(
        ">256s32sIIIHHHBBBBBB",
        b"/virtual/fido2/1-1",
        BUS_ID.encode(),
        1,
        1,
        2,
        VID,
        PID,
        0x0100,
        0,
        0,
        0,
        1,
        1,
        1,
    )


def string_descriptor(index):
    if index == 0:
        return b"\x04\x03\x09\x04"
    strings = {1: "Software Authenticator", 2: "Python FIDO2 Development Key", 3: "virtual-0001"}
    if index not in strings:
        return None
    text = strings[index].encode("utf-16-le")
    return bytes([len(text) + 2, 3]) + text


def control(setup, payload):
    kind, request, value, index, length = struct.unpack("<BBHHH", setup)
    if kind == 0x80 and request == 6:
        descriptor_type, number = value >> 8, value & 0xFF
        if descriptor_type == 1 and number == 0:
            return 0, DEVICE_DESCRIPTOR[:length]
        if descriptor_type == 2 and number == 0:
            return 0, CONFIG_DESCRIPTOR[:length]
        if descriptor_type == 3:
            descriptor = string_descriptor(number)
            if descriptor is not None:
                return 0, descriptor[:length]
    if kind == 0x81 and request == 6 and index == 0:
        descriptor = {0x21: HID_DESCRIPTOR, 0x22: REPORT_DESCRIPTOR}.get(value >> 8)
        if descriptor is not None:
            return 0, descriptor[:length]
    if kind in (0x80, 0x81, 0x82) and request == 0:
        return 0, bytes(2)[:length]
    if kind == 0x80 and request == 8:
        return 0, b"\x01"[:length]
    if kind == 0x81 and request == 10:
        return 0, b"\x00"[:length]
    if kind == 0 and request in (5, 9):  # SET_ADDRESS, SET_CONFIGURATION
        return 0, b""
    if kind in (0x01, 0x02) and request in (1, 3, 11):
        return 0, b""
    if kind == 0x21 and index == 0 and request in (10, 11):  # HID idle / protocol
        return 0, b""
    if kind == 0xA1 and index == 0 and request in (2, 3):
        return 0, (b"\x00" if request == 2 else b"\x01")[:length]
    return -32, b""  # Stall unsupported requests rather than inventing a response.


class Connection:
    def __init__(self, reader, writer, authenticator, gate):
        self.reader, self.writer = reader, writer
        self.reports = deque()
        self.reads = deque()
        self.hid = HidDevice(authenticator, self.emit)
        self.gate = gate
        self.hid.touch_pending = lambda: self.gate.pending is not None

    def reply(self, seq, status=0, data=b"", actual=None):
        header = struct.pack(
            ">IIIIIiiiii8s",
            3,
            seq,
            0,
            0,
            0,
            status,
            len(data) if actual is None else actual,
            0,
            0,
            0,
            bytes(8),
        )
        self.writer.write(header + data)

    def emit(self, report):
        if self.writer.is_closing():
            return
        if len(self.reports) >= 1024:
            self.writer.close()
            return
        self.reports.append(report)
        self.flush()

    def flush(self):
        while self.reads and self.reports:
            seq, size = self.reads.popleft()
            self.reply(seq, data=self.reports.popleft()[:size])

    async def run(self):
        try:
            while True:
                raw = await self.reader.readexactly(48)
                command, seq, device, direction, endpoint = struct.unpack(">IIIII", raw[:20])
                if command == 2:
                    target = int.from_bytes(raw[20:24], "big")
                    exists = any(item[0] == target for item in self.reads)
                    self.reads = deque(item for item in self.reads if item[0] != target)
                    self.writer.write(
                        struct.pack(">IIIIIi24s", 4, seq, 0, 0, 0, -104 if exists else 0, bytes(24))
                    )
                    await self.writer.drain()
                    continue
                if command != 1 or direction not in (0, 1):
                    raise ValueError("Invalid USB/IP request")
                flags, size, start, count, interval = struct.unpack(">Iiiii", raw[20:40])
                if not 0 <= size <= 65536 or count not in (-1, 0):
                    raise ValueError("Invalid transfer size or unsupported isochronous transfer")
                payload = await self.reader.readexactly(size) if direction == 0 else b""
                if device != 0x10001:
                    self.reply(seq, -19)
                elif endpoint == 0:
                    setup = raw[40:48]
                    if setup[0] == 0x21 and setup[1] == 9 and len(payload) == 64:
                        self.hid.feed(payload)
                        self.reply(seq, actual=len(payload))
                    else:
                        status, data = control(setup, payload)
                        self.reply(
                            seq,
                            status,
                            data[:size] if direction else b"",
                            None if direction else len(payload),
                        )
                elif endpoint == 1 and direction == 0:
                    if len(payload) != 64:
                        self.reply(seq, -32)
                    else:
                        self.hid.feed(payload)
                        self.reply(seq, actual=64)
                elif endpoint == 1 and direction == 1 and size >= 64:
                    if len(self.reads) >= 128:
                        raise ValueError("Too many outstanding interrupt reads")
                    self.reads.append((seq, size))
                    self.flush()
                else:
                    self.reply(seq, -32)
                await self.writer.drain()
        finally:
            await self.hid.close()


class UsbIpServer:
    def __init__(self, authenticator, gate):
        self.authenticator = authenticator
        self.gate = gate
        self.connection = None
        self.stopping = False

    async def accept(self, reader, writer):
        imported = False
        try:
            header = await asyncio.wait_for(reader.readexactly(8), timeout=5)
            version, command, status = struct.unpack(">HHI", header)
            if version != VERSION or status != 0:
                return
            if command == 0x8005:
                available = self.connection is None
                writer.write(struct.pack(">HHII", VERSION, 5, 0, int(available)))
                if available:
                    writer.write(device_record() + bytes([3, 0, 0, 0]))
                await writer.drain()
            elif command == 0x8003:
                bus = await asyncio.wait_for(reader.readexactly(32), timeout=5)
                if bus.rstrip(b"\0") != BUS_ID.encode() or self.connection is not None:
                    writer.write(struct.pack(">HHI", VERSION, 3, 1))
                    await writer.drain()
                    return
                self.authenticator.power_on()
                self.connection = Connection(reader, writer, self.authenticator, self.gate)
                imported = True
                writer.write(struct.pack(">HHI", VERSION, 3, 0) + device_record())
                await writer.drain()
                LOG.info("Virtual FIDO2 device imported")
                await self.connection.run()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        except (ValueError, TimeoutError) as error:
            LOG.warning("Rejected USB/IP connection: %s", error)
        except Exception:
            LOG.exception("USB/IP connection failed")
        finally:
            if imported:
                self.connection = None
                self.authenticator.power_on()
                LOG.info("Virtual FIDO2 device disconnected")
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    def disconnect(self):
        if self.connection:
            self.connection.writer.close()
