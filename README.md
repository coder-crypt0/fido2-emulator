# Python FIDO2 USB emulator

A software CTAP2 authenticator that presents a virtual USB HID security key to
Windows through a signed USB/IP virtual host controller. Python handles USB
enumeration, CTAPHID, credential creation, signing, PIN operations, presence
approval, and plug/unplug control.

This is a development authenticator. Its keys live in software, encrypted at rest
with user-scoped Windows DPAPI. It cannot provide physical isolation, certified
hardware attestation, or emulate a device plugged into another computer through
an ordinary USB cable. Services requiring approved hardware attestation may reject
it. Use it for your own project's integration and testing; keep independent recovery
methods for real accounts.

## Quick start (Windows 10/11, Python 3.12+)

From the project folder in PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1
```

Install the signed virtual USB driver once, from an **Administrator PowerShell**:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-driver.ps1
```

The installer is pinned to usbip-win2 **0.9.8.1** and checked against its published
SHA-256 and a valid Authenticode signature before execution. It may briefly restart
USB hubs. It does not change Secure Boot or test-signing settings. The upstream
project recommends creating a restore point before installation. Driver downloads
and logs stay in the ignored `.downloads` directory.

Launch the panel by double-clicking `launch.cmd`, or:

```powershell
.\.venv\Scripts\python.exe -m fido2_emulator gui
```

1. Click **Plug in**. The controller attaches the Python USB/IP device to Windows.
2. In your application/browser, choose **Security key** when Windows asks for an
   authenticator. It may be under **Other options**.
3. The panel shows the requesting RP ID. Click **Touch key** to approve the operation.
4. Click **Unplug** to detach it. Replugging preserves registered credentials.

Touch approval expires after 30 seconds and cannot be banked in advance. Closing
the panel leaves the daemon/key running; use `stop` to shut it down.

## Python control API

```python
from fido2_emulator.controller import Emulator

key = Emulator()
key.plug()
print(key.status())
# Start a WebAuthn operation in your application, then approve its pending touch:
key.touch()
key.unplug()
key.stop()
```

The same operations are available from the terminal:

```powershell
.\.venv\Scripts\python.exe -m fido2_emulator doctor
.\.venv\Scripts\python.exe -m fido2_emulator plug
.\.venv\Scripts\python.exe -m fido2_emulator status
.\.venv\Scripts\python.exe -m fido2_emulator touch
.\.venv\Scripts\python.exe -m fido2_emulator unplug
.\.venv\Scripts\python.exe -m fido2_emulator stop
```

`serve` runs the daemon in the foreground for debugging. It supports `--usb-port`
and `--control-port` (defaults 3240 and 3241). Both bind exclusively to loopback.
`FIDO2_USBIP_EXE` overrides the client executable path.

## Local browser verification

```powershell
.\.venv\Scripts\python.exe -m fido2_emulator demo
```

Open the emulator panel and plug in the key. The demo opens
`http://localhost:8765`, supports registration and login, and independently verifies
the WebAuthn challenge, origin, RP hash, presence flag, and assertion signature using
Yubico's `Fido2Server`. Enable **Require PIN verification** to test the PIN flow.
Demo server registrations are in memory and disappear when it stops; authenticator
credentials remain encrypted in its store.

## Implemented / limitations

- CTAP 2.0 `getInfo`, `makeCredential`, `getAssertion`, `getNextAssertion`.
- ES256 (P-256), random credential IDs, RP isolation, exclusion checks, a monotonic
  signature counter, and up to 256 stored credentials.
- Discoverable/resident credentials and multiple-account assertions.
- ClientPIN protocol 1: set/change PIN, ECDH/AES/HMAC token exchange, PIN verification,
  8 persistent retries, and temporary lockout after 3 failures until replug.
- CTAPHID INIT/PING/CBOR/CANCEL, keepalives, fragmented messages, sequence validation,
  channel isolation, and reassembly timeout.
- USB/IP discovery/import, USB descriptors and control requests, interrupt IN/OUT,
  and cancellation of pending USB requests.
- Explicit user presence via the panel or authenticated local control channel.

No CTAP1/U2F, CTAP 2.1/2.2 conformance claim, FIDO certification, biometric UV,
credential-management command, hardware attestation, enterprise attestation,
`hmac-secret`/PRF, large blobs, or remote reset. PIN is optional until a client sets
one; after that registrations require a PIN token. A forgotten PIN is intentionally
not recoverable through CTAP reset. This does not impersonate a YubiKey model or
reuse another device's AAGUID or attestation identity. The VID/PID are development
identifiers, not a production allocation.

## Storage and process boundaries

Runtime data is outside the repository at `%LOCALAPPDATA%\Fido2Emulator`:

- `credentials.dpapi`: encrypted keys, credential metadata, counter, and PIN state.
- `runtime.dpapi`: encrypted per-run local control token and connection details.
- `daemon.log`: lifecycle/errors; no deliberate key/PIN/payload logging.

`FIDO2_EMULATOR_HOME` selects another local data directory. Backing up just the
encrypted store does not make it portable across Windows accounts or machines.
Losing it loses those credentials. Another process running as the same Windows user
can decrypt DPAPI data and control this authenticator; it is not a hardware trust
boundary. USB/IP on loopback is not authenticated: local software can issue CTAP
requests, as local software can access a physical authenticator. Touch remains an
explicit operation. Keep the daemon unplugged/stopped when unused.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
```

The automated suite drives the actual TCP USB/IP server using an independent host
adapter and Yubico's CTAPHID/CTAP2 client. It checks registration and signature
verification, RP isolation, exclusion, discoverable credentials, PIN exchange/change/
lockout, malformed messages, maximum HID fragmentation, cancellation, USB enumeration,
unlink semantics, touch expiry, and real DPAPI persistence/tamper rejection on Windows.
It does not substitute for an OS/browser test through the installed driver.
See [the verification record](docs/VERIFICATION.md) for the actual Windows HID
probe results and the boundary between tested behavior and remaining browser UI validation.

## Troubleshooting

- **No driver/client:** run the installation script as Administrator, then `doctor`.
- **Attach denied:** the driver may require elevation on a particular host; run
  the panel/CLI from an Administrator terminal if the driver reports access denied.
- **Browser offers Windows Hello:** choose another sign-in method, then security key.
  The authenticator reports itself as roaming (`plat=false`, USB transport).
- **Touch timeout:** restart the WebAuthn operation and approve the displayed RP ID.
- **Port in use / startup error:** inspect `%LOCALAPPDATA%\Fido2Emulator\daemon.log`.
- **Direct HID access denied:** Windows restricts FIDO HID access in ordinary
  processes. Browser/Windows WebAuthn can use it; low-level HID probes may need elevation.
- **Hardware policy rejection:** a software authenticator cannot satisfy a requirement
  for approved manufacturer attestation or physical key isolation.

## Design and sources

```text
Browser / Windows WebAuthn / HID client
             │
    Signed usbip-win2 UDE driver
             │  USB/IP over 127.0.0.1
    Python USB enumeration + CTAPHID
             │
    CTAP2 + ES256 + ClientPIN
             │
    Windows DPAPI credential store
```

Implementation references:

- [FIDO CTAP 2.1 specification](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html)
- [Linux USB/IP wire protocol](https://www.kernel.org/doc/html/latest/usb/usbip_protocol.html)
- [Microsoft USB device emulation architecture](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/usb-emulated-device--ude--architecture)
- [usbip-win2 signed Windows virtual controller](https://github.com/vadimgrn/usbip-win2)
- [Yubico python-fido2 client and relying party implementation](https://github.com/Yubico/python-fido2)
- [Technical Report on a Virtual CTAP2 WebAuthn Authenticator (2021)](https://arxiv.org/abs/2108.04131)

The authenticator and USB/IP implementation in this repository are Python code;
the required kernel driver is the separately installed upstream signed component.
