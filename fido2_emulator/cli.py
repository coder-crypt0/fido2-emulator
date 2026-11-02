import argparse
import asyncio
import json
import logging
import os
import platform
import sys

from .controller import Emulator, usbip_executable


def main():
    parser = argparse.ArgumentParser(description="Python virtual USB FIDO2 development key")
    commands = parser.add_subparsers(dest="command")
    for name in ("gui", "plug", "unplug", "touch", "status", "stop", "reset", "doctor", "demo"):
        commands.add_parser(name)
    serve = commands.add_parser("serve")
    serve.add_argument("--usb-port", type=int, default=3240)
    serve.add_argument("--control-port", type=int, default=3241)
    args = parser.parse_args()
    emulator = Emulator()
    try:
        if args.command in (None, "gui"):
            from .gui import run_gui

            run_gui()
        elif args.command == "serve":
            from .service import run

            logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
            # USB detach resets the TCP peer. The Windows Proactor loop in Python
            # 3.12 logs an uncaught shutdown error for that normal removal path.
            asyncio.run(
                run(args.usb_port, args.control_port), loop_factory=asyncio.SelectorEventLoop
            )
        elif args.command == "doctor":
            print(
                f"Platform: {platform.system()} {platform.release()}, "
                f"Python {platform.python_version()}"
            )
            if os.name != "nt":
                raise RuntimeError("Packaged controller requires Windows 10/11.")
            print("USB/IP client:", usbip_executable())
            import subprocess

            result = subprocess.run(
                [usbip_executable(), "port"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            print((result.stdout + result.stderr).strip())
            if result.returncode:
                raise RuntimeError(
                    "Virtual USB controller unavailable; install the driver or reboot."
                )
            print("Daemon:", json.dumps(emulator.status()))
        elif args.command == "demo":
            from .demo import run_demo

            run_demo()
        elif args.command == "status":
            print(json.dumps(emulator.status(), indent=2))
        elif args.command == "touch":
            print("Touch approved." if emulator.touch() else "No touch request pending.")
        else:
            result = getattr(emulator, args.command)()
            print(json.dumps(result) if result is not None else "Stopped.")
    except KeyboardInterrupt:
        pass
    except (RuntimeError, OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
