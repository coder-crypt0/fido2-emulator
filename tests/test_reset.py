import os

import pytest

from fido2_emulator.controller import Emulator
from fido2_emulator.storage import FileStore, MemoryStore


@pytest.mark.skipif(os.name != "nt", reason="Persistent store requires Windows DPAPI")
def test_reset_erases_keys_pin_and_additional_key_material(tmp_path, monkeypatch):
    monkeypatch.setenv("FIDO2_EMULATOR_HOME", str(tmp_path))
    path = tmp_path / "credentials.dpapi"
    store = FileStore(path)
    store.data.update(
        credentials=[{"id": "test", "key": "private-material"}],
        pin_hash="old-pin-hash",
        counter=42,
        u2f_attestation={"key": "test-attestation-key"},
    )
    store.save()
    result = Emulator().reset()
    assert result == {"reset": True, "credentials_removed": 1, "pin_set": False, "connected": False}
    assert FileStore(path).data == MemoryStore().data
    assert not (tmp_path / "runtime.dpapi").exists()


def test_reset_refuses_to_replace_store_when_daemon_cannot_stop(tmp_path, monkeypatch):
    monkeypatch.setenv("FIDO2_EMULATOR_HOME", str(tmp_path))
    path = tmp_path / "credentials.dpapi"
    path.write_bytes(b"preserve-existing-store")
    emulator = Emulator()
    monkeypatch.setattr(emulator, "stop", lambda: None)
    monkeypatch.setattr(emulator, "status", lambda: {"running": True})
    monkeypatch.setattr("fido2_emulator.controller.time.sleep", lambda delay: None)
    with pytest.raises(RuntimeError, match="refusing to reset a live credential store"):
        emulator.reset()
    assert path.read_bytes() == b"preserve-existing-store"


def test_status_tolerates_windows_runtime_file_removal_race(monkeypatch):
    def unavailable():
        raise PermissionError("State file is being removed")

    monkeypatch.setattr("fido2_emulator.controller.read_runtime", unavailable)
    assert Emulator().status() == {"running": False, "connected": False}


def test_reset_refuses_stale_runtime_file_even_when_status_is_unavailable(tmp_path, monkeypatch):
    monkeypatch.setenv("FIDO2_EMULATOR_HOME", str(tmp_path))
    path = tmp_path / "credentials.dpapi"
    path.write_bytes(b"preserve-existing-store")
    (tmp_path / "runtime.dpapi").write_bytes(b"unavailable-runtime")
    emulator = Emulator()
    monkeypatch.setattr(emulator, "stop", lambda: None)
    monkeypatch.setattr(emulator, "status", lambda: {"running": False})
    monkeypatch.setattr("fido2_emulator.controller.time.sleep", lambda delay: None)
    with pytest.raises(RuntimeError, match="refusing to reset a live credential store"):
        emulator.reset()
    assert path.read_bytes() == b"preserve-existing-store"
