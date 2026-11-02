"""64-byte CTAPHID framing with channel isolation, cancellation, and keepalives."""

import asyncio
import secrets
import struct
import time

from .authenticator import MAX_MESSAGE

BROADCAST = 0xFFFFFFFF


def packets(channel, command, data):
    if len(data) > MAX_MESSAGE:
        raise ValueError("CTAPHID message too large")
    yield (struct.pack(">IBH", channel, command | 0x80, len(data)) + data[:57]).ljust(64, b"\0")
    for index, start in enumerate(range(57, len(data), 59)):
        yield (struct.pack(">IB", channel, index) + data[start : start + 59]).ljust(64, b"\0")


class HidDevice:
    def __init__(self, authenticator, emit):
        self.authenticator = authenticator
        self.emit = emit
        self.channels = set()
        self.partial = None
        self.partial_timer = None
        self.task = None
        self.active_channel = None
        self.touch_pending = lambda: False

    def send(self, channel, command, data):
        for packet in packets(channel, command, data):
            self.emit(packet)

    def error(self, channel, code):
        self.send(channel, 0x3F, bytes([code]))

    def clear_partial(self):
        if self.partial_timer:
            self.partial_timer.cancel()
        self.partial_timer = None
        self.partial = None

    def expire(self):
        if self.partial:
            channel = self.partial[0]
            self.clear_partial()
            self.error(channel, 0x05)

    def feed(self, packet):
        if len(packet) != 64:
            return
        channel, tag = struct.unpack(">IB", packet[:5])
        if tag & 0x80:
            command = tag & 0x7F
            length = int.from_bytes(packet[5:7], "big")
            if channel == 0 or (channel == BROADCAST and command != 0x06):
                self.error(channel, 0x0B)
                return
            if channel != BROADCAST and channel not in self.channels:
                self.error(channel, 0x0B)
                return
            if command == 0x06:
                if length != 8:
                    self.error(channel, 0x03)
                    return
                if channel == self.active_channel:
                    self.task.cancel()
                    self.active_channel = None
                if self.partial and self.partial[0] == channel:
                    self.clear_partial()
                if channel == BROADCAST:
                    if len(self.channels) >= 64:
                        self.error(channel, 0x06)
                        return
                    assigned = secrets.randbelow(0xFFFFFFFE) + 1
                    while assigned in self.channels:
                        assigned = secrets.randbelow(0xFFFFFFFE) + 1
                    self.channels.add(assigned)
                else:
                    assigned = channel
                # CTAP HID version 2, firmware 0.1.0, CBOR + NMSG capabilities.
                self.send(
                    channel,
                    command,
                    packet[7:15] + struct.pack(">IBBBBB", assigned, 2, 0, 1, 0, 0x0C),
                )
                return
            if command == 0x11:
                if length == 0 and channel == self.active_channel and self.task:
                    self.task.cancel()
                return
            if self.active_channel is not None or self.partial:
                self.error(channel, 0x06)
                return
            if length > MAX_MESSAGE:
                self.error(channel, 0x03)
                return
            if length <= 57:
                self.dispatch(channel, command, packet[7 : 7 + length])
            else:
                self.partial = [channel, command, length, bytearray(packet[7:]), 0]
                self.partial_timer = asyncio.get_running_loop().call_later(3, self.expire)
        else:
            if not self.partial:
                return
            active, command, length, data, sequence = self.partial
            if channel != active:
                self.error(channel, 0x06)
                return
            if tag != sequence:
                self.clear_partial()
                self.error(channel, 0x04)
                return
            data.extend(packet[5:])
            self.partial[4] += 1
            if len(data) >= length:
                self.clear_partial()
                self.dispatch(channel, command, bytes(data[:length]))

    def dispatch(self, channel, command, data):
        if command == 0x01:
            self.send(channel, command, data)
        elif command == 0x10:
            self.active_channel = channel
            self.task = asyncio.create_task(self.execute(channel, data))
        else:
            self.error(channel, 0x01)

    async def execute(self, channel, data):
        async def keepalive():
            while True:
                await asyncio.sleep(0.1)
                self.send(channel, 0x3B, bytes([2 if self.touch_pending() else 1]))

        ticker = asyncio.create_task(keepalive())
        current = asyncio.current_task()
        try:
            response = await self.authenticator.handle(data)
            if self.task is current:
                self.send(channel, 0x10, response)
        except asyncio.CancelledError:
            if self.task is current and self.active_channel == channel:
                self.send(channel, 0x10, b"\x2d")
        finally:
            ticker.cancel()
            if self.task is current:
                self.active_channel = None

    async def close(self):
        self.clear_partial()
        if self.task:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)


class TouchGate:
    def __init__(self):
        self.pending = None
        self.event = asyncio.Event()

    async def request(self, operation, rp_id):
        self.event.clear()
        self.pending = {"operation": operation, "rp": rp_id, "since": time.time()}
        try:
            await self.event.wait()
            return True
        finally:
            self.pending = None
            self.event.clear()

    def touch(self):
        if self.pending is None:
            return False
        self.event.set()
        return True
