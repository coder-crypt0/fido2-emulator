"""Python plug/unplug/touch API for the local virtual authenticator."""

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

from .service import data_directory, read_runtime
from .storage import FileStore, MemoryStore, encode_passphrase
from .usb_drive import drive_letter


def usbip_executable():
    candidates = [
        os.environ.get("FIDO2_USBIP_EXE"),
        shutil.which("usbip"),
        str(Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "USBip" / "usbip.exe"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(Path(candidate).resolve())
    raise RuntimeError(
        "USB/IP client not installed. Run scripts/install-driver.ps1 as Administrator."
    )


class Emulator:
    def request(self, command, **kwargs):
        try:
            runtime = read_runtime()
            with socket.create_connection(
                ("127.0.0.1", runtime["control_port"]), timeout=3
            ) as sock:
                sock.sendall(
                    json.dumps({"token": runtime["token"], "command": command, **kwargs}).encode()
                    + b"\n"
                )
                with sock.makefile("rb") as file:
                    result = json.loads(file.readline(8192))
        except (OSError, ValueError) as error:
            raise RuntimeError("Emulator daemon is unavailable; restart with 'serve'.") from error
        if not result.get("ok"):
            raise RuntimeError("Emulator control command failed")
        return result

    def status(self):
        try:
            return self.request("status")
        except (RuntimeError, OSError, ValueError):
            return {"running": False, "connected": False}

    def start(self, usb_drive=None, unlock=None):
        if usb_drive:
            usb_drive = drive_letter(usb_drive)
        status = self.status()
        if status["running"]:
            if status.get("usb_drive") != usb_drive:
                raise RuntimeError("Stop the running key before switching credential stores.")
            return True
        if os.name != "nt":
            raise RuntimeError("The packaged daemon uses Windows DPAPI and requires Windows.")
        command = [sys.executable, "-m", "fido2_emulator", "serve"]
        if usb_drive:
            if unlock is None:
                raise ValueError("USB drive mode requires a vault passphrase.")
            passphrase = unlock()
            if passphrase is None:
                return False
            encode_passphrase(passphrase)
            secret = json.dumps(passphrase).encode("ascii") + b"\n"
            del passphrase
            command.extend(["--usb-drive", usb_drive])
        directory = data_directory()
        directory.mkdir(parents=True, exist_ok=True)
        with (directory / "daemon.log").open("ab") as log:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE if usb_drive else subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.PIPE if usb_drive else log,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        try:
            if process.stdin:
                try:
                    with process.stdin:
                        process.stdin.write(secret)
                except BrokenPipeError:
                    pass
                del secret
            for _ in range(100):
                if process.poll() is not None:
                    if process.stderr:
                        message = process.stderr.read().decode(errors="replace").strip()
                        if message:
                            raise RuntimeError(message.removeprefix("Error: "))
                    break
                status = self.status()
                if status["running"]:
                    if status.get("usb_drive") != usb_drive:
                        raise RuntimeError(
                            "Stop the running key before switching credential stores."
                        )
                    return True
                time.sleep(0.1)
            if process.poll() is None:
                process.terminate()
                process.wait(5)
        finally:
            if process.stderr:
                process.stderr.close()
        raise RuntimeError(f"Daemon did not start. Inspect {directory / 'daemon.log'}")

    def plug(self, usb_drive=None, unlock=None):
        executable = usbip_executable()
        if usb_drive:
            usb_drive = drive_letter(usb_drive)
        if not self.start(usb_drive, unlock):
            return self.status()
        status = self.status()
        if not status["running"]:
            raise RuntimeError("The key stopped before it could be attached.")
        if status.get("usb_drive") != usb_drive:
            raise RuntimeError("Stop the running key before switching credential stores.")
        if status["connected"]:
            return status
        try:
            return self._attach(executable)
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            if usb_drive and self.status().get("usb_drive") == usb_drive:
                try:
                    self.request("disconnect")
                except RuntimeError:
                    pass
            if isinstance(error, subprocess.TimeoutExpired):
                raise RuntimeError(
                    "The virtual USB driver timed out while attaching the key."
                ) from error
            raise

    def _attach(self, executable):
        runtime = read_runtime()
        result = subprocess.run(
            [
                executable,
                "--tcp-port",
                str(runtime["usb_port"]),
                "attach",
                "-r",
                "127.0.0.1",
                "-b",
                "1-1",
                "--once",
                "--terse",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        if result.returncode:
            raise RuntimeError(
                (result.stderr + result.stdout).strip()
                or "USB attach failed; check the driver with 'doctor'."
            )
        match = re.search(r"(?:^|\n)\s*(\d+)\s*(?:\n|$)", result.stdout)
        if not match:
            raise RuntimeError("USB/IP did not report a port number: " + result.stdout.strip())
        self.request("set_port", port=int(match[1]))
        for _ in range(50):
            if self.status()["connected"]:
                return self.status()
            time.sleep(0.1)
        raise RuntimeError("Driver accepted attach, but did not import the virtual USB device.")

    def unplug(self):
        status = self.status()
        if not status["running"]:
            return status
        if status.get("usb_drive"):
            # Lock the vault even if the driver has already dropped the connection.
            self.request("disconnect")
            return {"running": False, "connected": False}
        # Closing the import connection simulates physical removal. No global detach.
        if status["connected"] and status.get("port") is not None:
            result = subprocess.run(
                [usbip_executable(), "detach", "-p", str(status["port"])],
                capture_output=True,
                text=True,
                timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            if result.returncode:
                raise RuntimeError((result.stderr + result.stdout).strip())
        self.request("disconnect")
        return {"running": True, "connected": False}

    def touch(self):
        return self.request("touch")["accepted"]

    def stop(self):
        if self.unplug()["running"]:
            self.request("stop")

    def reset(self):
        """Erase the local Windows credentials and PIN."""
        if self.status().get("usb_drive"):
            raise RuntimeError("Unplug the USB key before resetting the local Windows store.")
        self.stop()
        for _ in range(100):
            if not (data_directory() / "runtime.dpapi").exists() and not self.status()["running"]:
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("Daemon did not stop; refusing to reset a live credential store.")
        store = FileStore(data_directory() / "credentials.dpapi")
        count = len(store.data["credentials"])
        store.data = MemoryStore().data
        store.save()
        return {"reset": True, "credentials_removed": count, "pin_set": False, "connected": False}
