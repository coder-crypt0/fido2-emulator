"""Identify a Windows USB storage volume by its mount-manager GUID."""

import ctypes
import os
import re
from contextlib import contextmanager
from ctypes import wintypes
from pathlib import Path


def drive_letter(name):
    if not re.fullmatch(r"[a-zA-Z]:[\\/]?", name):
        raise ValueError("Enter a USB drive letter such as E:.")
    return name[:2].upper()


class UsbDrive:
    def __init__(self, letter):
        self.letter = drive_letter(letter)
        if os.name != "nt":
            raise RuntimeError("USB drive mode requires Windows.")
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.get_volume_name = self.kernel.GetVolumeNameForVolumeMountPointW
        self.get_volume_name.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
        self.get_volume_name.restype = wintypes.BOOL
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL
        try:
            self.volume = self.current_volume()
            if self.bus_type() != 7:  # BusTypeUsb, including USB drives reported as fixed
                raise ValueError(f"{self.letter} is not a USB storage volume.")
        except OSError as error:
            raise OSError(
                f"Unable to identify the USB storage volume {self.letter}: {error}"
            ) from error
        self.root = Path(self.volume)

    def current_volume(self):
        buffer = ctypes.create_unicode_buffer(50)
        if not self.get_volume_name(self.letter + "\\", buffer, len(buffer)):
            raise ctypes.WinError(ctypes.get_last_error())
        return buffer.value

    def check(self):
        if self.current_volume().casefold() != self.volume.casefold():
            raise OSError(f"The USB storage volume at {self.letter} changed.")

    def bus_type(self):
        open_volume = self.kernel.CreateFileW
        open_volume.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        open_volume.restype = wintypes.HANDLE
        handle = open_volume(self.volume.rstrip("\\"), 0, 7, None, 3, 0, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            query_property = self.kernel.DeviceIoControl
            query_property.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
                ctypes.c_void_p,
            ]
            query_property.restype = wintypes.BOOL
            query = bytes(12)  # StorageDeviceProperty, PropertyStandardQuery
            result = ctypes.create_string_buffer(4096)
            received = wintypes.DWORD()
            if not query_property(
                handle,
                0x2D1400,
                query,
                len(query),
                result,
                len(result),
                ctypes.byref(received),
                None,
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            if received.value < 32:
                raise OSError("Windows returned an incomplete storage device descriptor.")
            return int.from_bytes(result[28:32], "little")
        finally:
            self.kernel.CloseHandle(handle)

    @contextmanager
    def lock(self):
        """Exclude concurrent writers without keeping an open file on the drive."""
        create_mutex = self.kernel.CreateMutexW
        create_mutex.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        create_mutex.restype = wintypes.HANDLE
        mutex_name = "Global\\Fido2Emulator-" + self.volume.split("{", 1)[1].rstrip("\\}").lower()
        ctypes.set_last_error(0)
        handle = create_mutex(None, False, mutex_name)
        error = ctypes.get_last_error()
        if not handle:
            raise ctypes.WinError(error)
        try:
            if error == 183:  # ERROR_ALREADY_EXISTS
                raise RuntimeError(f"The passkey vault on {self.letter} is already in use.")
            yield
        finally:
            self.kernel.CloseHandle(handle)
