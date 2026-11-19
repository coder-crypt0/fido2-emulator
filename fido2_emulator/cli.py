import argparse
import asyncio
import json
import logging
import os
import platform
import sys
from getpass import getpass

from .controller import Emulator, usbip_executable
from .storage import PortableStore
from .usb_drive import UsbDrive, drive_letter


def drive_argument(name):
    try:
        return drive_letter(name)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def vault_passphrase(prompt="USB vault passphrase: "):
    if not sys.stdin or not sys.stdin.isatty():
        raise RuntimeError("Enter the vault passphrase from an interactive terminal or the panel.")
    try:
        return getpass(prompt)
    except EOFError:
        raise RuntimeError("No vault passphrase was entered.") from None


def daemon_passphrase():
    if sys.stdin and not sys.stdin.isatty():
        try:
            secret = json.loads(sys.stdin.buffer.readline(65536))
        except ValueError:
            raise ValueError("The daemon did not receive a vault passphrase.") from None
        if not isinstance(secret, str):
            raise ValueError("The daemon did not receive a vault passphrase.")
        return secret
    return vault_passphrase()


def main():
    parser = argparse.ArgumentParser(description="Python virtual USB FIDO2 development key")
    commands = parser.add_subparsers(dest="command")
    for name in ("unplug", "touch", "status", "stop", "doctor", "demo"):
        commands.add_parser(name)
    commands.add_parser("reset", help="Erase credentials from the local Windows store")
    serve = commands.add_parser("serve")
    serve.add_argument("--usb-port", type=int, default=3240)
    serve.add_argument("--control-port", type=int, default=3241)
    for command in (serve, commands.add_parser("gui"), commands.add_parser("plug")):
        command.add_argument("--usb-drive", type=drive_argument, help="USB drive letter, e.g. E:")
    commands.add_parser(
        "init-usb", help="Create an encrypted passkey vault on a USB drive"
    ).add_argument("drive", type=drive_argument)
    args = parser.parse_args()
    emulator = Emulator()
    try:
        if args.command in (None, "gui"):
            from .gui import run_gui

            run_gui(getattr(args, "usb_drive", None))
        elif args.command == "init-usb":
            drive = UsbDrive(args.drive)
            passphrase = vault_passphrase()
            if passphrase != vault_passphrase("Confirm USB vault passphrase: "):
                raise ValueError("Vault passphrases did not match.")
            PortableStore.initialize(drive, passphrase)
            print(f"Created the encrypted passkey vault on {drive.letter}.")
        elif args.command == "plug":
            print(json.dumps(emulator.plug(args.usb_drive, vault_passphrase)))
        elif args.command == "serve":
            from .service import run

            logging.basicConfig(
                level=logging.INFO,
                format="%(asctime)s %(levelname)s %(message)s",
                stream=sys.stdout,
            )
            drive = UsbDrive(args.usb_drive) if args.usb_drive else None
            # USB detach resets the TCP peer. The Windows Proactor loop in Python
            # 3.12 logs an uncaught shutdown error for that normal removal path.
            asyncio.run(
                run(
                    args.usb_port,
                    args.control_port,
                    usb_drive=drive,
                    passphrase=daemon_passphrase() if drive else None,
                ),
                loop_factory=asyncio.SelectorEventLoop,
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
