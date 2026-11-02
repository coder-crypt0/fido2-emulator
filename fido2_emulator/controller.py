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
        runtime = read_runtime()
        try:
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
        except RuntimeError:
            return {"running": False, "connected": False}

    def start(self):
        if self.status()["running"]:
            return
        if os.name != "nt":
            raise RuntimeError("The packaged daemon uses Windows DPAPI and requires Windows.")
        directory = data_directory()
        directory.mkdir(parents=True, exist_ok=True)
        with (directory / "daemon.log").open("ab") as log:
            process = subprocess.Popen(
                [sys.executable, "-m", "fido2_emulator", "serve"],
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=log,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        for _ in range(100):
            if self.status()["running"]:
                return
            if process.poll() is not None:
                break
            time.sleep(0.1)
        raise RuntimeError(f"Daemon did not start. Inspect {directory / 'daemon.log'}")

    def plug(self):
        executable = usbip_executable()
        self.start()
        if self.status()["connected"]:
            return self.status()
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
        if self.status()["running"]:
            self.unplug()
            self.request("stop")
