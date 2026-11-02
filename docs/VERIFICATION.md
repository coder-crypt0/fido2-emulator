# Verification record

Verified on 2026-11-02 using Windows 11 (build 26200), Python 3.12.6, and the
upstream signed usbip-win2 0.9.8.1 x64 driver.

## Results

- Automated suite: **21 passed**, including the real TCP USB/IP transport,
  Yubico CTAPHID/CTAP2 interoperability, full relying-party verification,
  discoverable credentials, PIN exchange/change/lockout, cancellation, exclusion,
  RP isolation, USB descriptors/unlink, authenticated touch control, and DPAPI.
- Explicit local reset: verified removal of all three stored credentials and the
  PIN, with counter zero and device unplugged. Tests cover rejection when shutdown
  is incomplete and the Windows runtime-file removal race.
- Ruff lint and formatting checks: passed.
- `pip check`: no broken requirements.
- Windows Plug and Play enumerated `USB\VID_1209&PID_F1D0\VIRTUAL-0001` as a
  USB Input Device and its HID child as **HID-compliant fido**, both with OK status.
- Actual Windows HID probe (elevated Yubico client): `getInfo`, credential
  creation, assertion, and public-key signature verification passed.
- Actual Python-controlled unplug/replug: passed; the previously registered
  credential produced a valid assertion after reattachment.
- Daemon stop/start and another unplug/replug: stored credential count persisted.
- Native control panel inspected on the desktop: connected state and touch controls
  displayed correctly.

The browser demo's HTTP registration/login routes were tested with real
cryptographic responses. The native Windows WebAuthn browser dialog was not
automated; end-to-end Chrome/Edge UI interoperability is not claimed as verified.
FIDO certification and complete CTAP conformance are not claimed.

## Installed driver

The installer had a valid Windows Authenticode signature. Its SHA-256 matched
the digest published with the upstream GitHub release:

```text
38cad6d4432b52d5bb9409d9ad03b72fdffc4ada4cd3a48fbeca1a2752a8518a
```

Installation completed and the virtual controller worked without a reboot.
Windows nevertheless requested a reboot to finish the USB filter installation;
restart at a convenient time. No reboot was initiated, and no Secure Boot or
test-signing setting was changed.

## Reproduce the host probe

Plug the key in first. From an Administrator PowerShell:

```powershell
.\.venv\Scripts\python.exe .\scripts\probe-hardware.py --auto-touch --replug
```

The opt-in `--auto-touch` flag approves only the probe's randomly named local
`probe-<opaque-id>.example.test` RP. The application daemon still requires explicit
presence. Omit that flag to approve both probe touches manually in the panel.
The probe creates one persistent development credential and sends no traffic
outside the local machine. It intentionally stops if the key already has a PIN;
use the browser demo for that case.
