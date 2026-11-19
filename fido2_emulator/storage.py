"""Credential stores for Windows DPAPI and passphrase-protected USB storage."""

import ctypes
import json
import os
import secrets
import stat
import tempfile
from ctypes import wintypes
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

VAULT_NAME = "Fido2Emulator.vault"
VAULT_HEADER = b"FIDO2-ARGON2ID-AESGCM-1\n"
MAX_VAULT_SIZE = 16 * 1024 * 1024


class Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def dpapi(data: bytes, *, decrypt: bool = False) -> bytes:
    if os.name != "nt":
        raise RuntimeError("Persistent storage requires Windows DPAPI; use MemoryStore for tests.")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    source = Blob(len(data), buffer)
    target = Blob()
    func = crypt32.CryptUnprotectData if decrypt else crypt32.CryptProtectData
    func.argtypes = [
        ctypes.POINTER(Blob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(Blob),
    ]
    func.restype = wintypes.BOOL
    # CRYPTPROTECT_UI_FORBIDDEN: never show UI inside the daemon.
    if not func(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(target)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(target.pbData, target.cbData)
    finally:
        kernel32.LocalFree(target.pbData)


class MemoryStore:
    def __init__(self):
        self.data = {"credentials": [], "counter": 0, "pin_hash": None, "retries": 8}

    def save(self):
        pass


class FileStore(MemoryStore):
    def __init__(self, path: Path):
        super().__init__()
        self.path = path
        if path.exists():
            raw = path.read_bytes()
            if not raw.startswith(b"FIDO2-DPAPI-1\n"):
                raise ValueError("Unrecognized credential store; refusing to overwrite it.")
            self.data = json.loads(dpapi(raw.split(b"\n", 1)[1], decrypt=True))

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        raw = b"FIDO2-DPAPI-1\n" + dpapi(json.dumps(self.data).encode())
        temporary = self.path.with_suffix(".tmp")
        with temporary.open("wb") as file:
            file.write(raw)
            file.flush()
            os.fsync(file.fileno())
        temporary.replace(self.path)


def encode_passphrase(passphrase: str):
    encoded = passphrase.encode("utf-8")
    if not 1 <= len(encoded) <= 1024:
        raise ValueError("Enter a vault passphrase of up to 1024 UTF-8 bytes.")
    return encoded


def vault_cipher(passphrase: str, salt: bytes):
    key = Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=64 * 1024).derive(
        encode_passphrase(passphrase)
    )
    return AESGCM(key)


class PortableStore(MemoryStore):
    def __init__(self, drive, passphrase: str):
        super().__init__()
        self.drive = drive
        self.path = drive.root / VAULT_NAME
        self.failed = False
        self.check()
        with self.path.open("rb") as file:
            raw = file.read(MAX_VAULT_SIZE + 1)
        offset = len(VAULT_HEADER)
        if not raw.startswith(VAULT_HEADER) or not offset + 44 <= len(raw) <= MAX_VAULT_SIZE:
            raise ValueError("Invalid or unsupported passkey vault file.")
        self.header = raw[: offset + 16]
        self.cipher = vault_cipher(passphrase, self.header[offset:])
        nonce = raw[offset + 16 : offset + 28]
        try:
            self.data = json.loads(self.cipher.decrypt(nonce, raw[offset + 28 :], self.header))
        except InvalidTag:
            raise ValueError("Incorrect vault passphrase or damaged passkey vault.") from None
        self.check()

    @staticmethod
    def initialize(drive, passphrase: str):
        path = drive.root / VAULT_NAME
        with drive.lock():
            drive.check()
            if os.path.lexists(path):
                raise FileExistsError(f"A passkey vault already exists on {drive.letter}.")
            if len(passphrase) < 4:
                raise ValueError("Use a vault passphrase of at least 4 characters.")
            salt = secrets.token_bytes(16)
            header = VAULT_HEADER + salt
            cipher = vault_cipher(passphrase, salt)
            PortableStore.write(path, MemoryStore().data, cipher, header, drive.check, create=True)

    def check(self):
        if self.failed:
            raise OSError("The USB passkey vault is no longer available.")
        self.drive.check()
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            raise FileNotFoundError(
                f"No passkey vault found on {self.drive.letter}. "
                f"Run 'init-usb {self.drive.letter}'."
            ) from None
        if not stat.S_ISREG(info.st_mode) or (
            getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise OSError("The passkey vault must be a regular file on the USB volume.")

    def save(self):
        try:
            self.check()
            self.write(self.path, self.data, self.cipher, self.header, self.check)
        except OSError:
            self.failed = True
            raise

    @staticmethod
    def write(path, data, cipher, header, check, *, create=False):
        nonce = secrets.token_bytes(12)
        raw = header + nonce + cipher.encrypt(nonce, json.dumps(data).encode(), header)
        if len(raw) > MAX_VAULT_SIZE:
            raise OSError("The passkey vault is full.")
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=path.parent, prefix=".fido2-vault-", suffix=".tmp", delete=False
            ) as file:
                temporary = Path(file.name)
                file.write(raw)
                file.flush()
                os.fsync(file.fileno())
            check()
            if create:
                temporary.rename(path)
            else:
                temporary.replace(path)
        finally:
            if temporary:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    # A surprise removal may leave an encrypted temporary file behind.
                    pass
