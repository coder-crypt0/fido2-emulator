"""Daemon lifecycle and authenticated, user-local control channel."""

import asyncio
import hmac
import json
import logging
import os
import secrets
from contextlib import nullcontext
from pathlib import Path

from .authenticator import Authenticator
from .hid import TouchGate
from .storage import FileStore, PortableStore, dpapi
from .usbip import UsbIpServer


def data_directory():
    override = os.environ.get("FIDO2_EMULATOR_HOME")
    if override:
        return Path(override).resolve()
    return Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "Fido2Emulator"


def read_runtime():
    path = data_directory() / "runtime.dpapi"
    if not path.exists():
        raise RuntimeError("Emulator is not running. Use 'plug' or 'serve'.")
    return json.loads(dpapi(path.read_bytes(), decrypt=True))


async def run(usb_port=3240, control_port=3241, *, usb_drive=None, passphrase=None):
    directory = data_directory()
    directory.mkdir(parents=True, exist_ok=True)
    with usb_drive.lock() if usb_drive else nullcontext():
        store = (
            PortableStore(usb_drive, passphrase)
            if usb_drive
            else FileStore(directory / "credentials.dpapi")
        )
        del passphrase
        await serve(store, directory, usb_port, control_port, usb_drive)


async def serve(store, directory, usb_port, control_port, usb_drive):
    gate = TouchGate()
    authenticator = Authenticator(store, gate.request)
    stopped = asyncio.Event()
    token = secrets.token_hex(32)
    attached_port = None

    def key_available():
        if stopped.is_set():
            return False
        if usb_drive:
            try:
                store.check()
            except OSError as error:
                logging.info("Locking USB passkey vault: %s", error)
                stopped.set()
                usb.disconnect()
                return False
        return True

    usb = UsbIpServer(authenticator, gate, available=key_available)

    async def monitor_vault():
        while key_available():
            await asyncio.sleep(0.25)

    async def control(reader, writer):
        nonlocal attached_port
        try:
            line = await asyncio.wait_for(reader.readline(), 5)
            request = json.loads(line)
            if (
                not isinstance(request, dict)
                or not isinstance(request.get("token"), str)
                or len(request["token"]) != 64
                or not request["token"].isascii()
            ):
                raise ValueError("Invalid control request")
            if not hmac.compare_digest(request["token"], token):
                raise ValueError("Control authentication failed")
            if not key_available():
                return
            command = request.get("command")
            result = {}
            if command == "status":
                result = {
                    "running": True,
                    "connected": usb.connection is not None,
                    "pending": gate.pending,
                    "port": attached_port,
                    "credentials": len(store.data["credentials"]),
                    "pin_set": store.data["pin_hash"] is not None,
                }
                if usb_drive:
                    result["usb_drive"] = usb_drive.letter
            elif command == "touch":
                result = {"accepted": gate.touch()}
            elif command == "set_port":
                require_port = request.get("port")
                if type(require_port) is not int or not 1 <= require_port <= 65535:
                    raise ValueError("Invalid attached port")
                attached_port = require_port
            elif command == "disconnect":
                usb.disconnect()
                attached_port = None
                if usb_drive:
                    stopped.set()
            elif command == "stop":
                stopped.set()
            else:
                raise ValueError("Unknown control command")
            writer.write(json.dumps({"ok": True, **result}).encode() + b"\n")
            await writer.drain()
        except (ValueError, TimeoutError, ConnectionError, asyncio.LimitOverrunError) as error:
            logging.warning("Rejected control request: %s", error)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    # Bind both sockets before publishing a runtime file; no firewall rule is needed.
    async with await asyncio.start_server(usb.accept, "127.0.0.1", usb_port):
        async with await asyncio.start_server(control, "127.0.0.1", control_port, limit=4096):
            runtime = {
                "pid": os.getpid(),
                "token": token,
                "usb_port": usb_port,
                "control_port": control_port,
            }
            state = directory / "runtime.dpapi"
            state.write_bytes(dpapi(json.dumps(runtime).encode()))
            logging.info("USB/IP listening on 127.0.0.1:%s", usb_port)
            monitor = asyncio.create_task(monitor_vault()) if usb_drive else None
            try:
                await stopped.wait()
            finally:
                if monitor:
                    monitor.cancel()
                    await asyncio.gather(monitor, return_exceptions=True)
                usb.disconnect()
                await asyncio.sleep(0)
                state.unlink(missing_ok=True)
