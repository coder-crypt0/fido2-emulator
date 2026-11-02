"""Persist the entire key store with Windows user-scoped DPAPI protection."""

import ctypes
import json
import os
from ctypes import wintypes
from pathlib import Path


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
