# Python FIDO2 USB emulator

A software CTAP2 authenticator that presents a virtual USB HID security key to
Windows through a signed USB/IP virtual host controller. It can store passkeys in
a Windows user-scoped DPAPI store or a passphrase-encrypted vault on a standard USB
flash drive. Python handles signing and touch approval on the Windows host.

A storage-only flash drive exposes USB mass storage. The emulator and driver supply
the FIDO interface on each Windows PC you use. The host handles decrypted keys while
the vault is open, and the vault file can be copied. Sites that require approved
hardware attestation may reject this software authenticator.

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

## Use a USB flash drive

Install the application and signed driver as above on each Windows PC. Insert a
writable USB drive and use its assigned drive letter. Initialize the vault once,
using a strong passphrase, then open the USB-mode panel. For a drive mounted as
`E:`, run these commands from the project folder.

```powershell
.\.venv\Scripts\python.exe -m fido2_emulator init-usb E:
.\launch.cmd --usb-drive E:
```

Choose **Plug in** and enter your vault passphrase. In your browser, select
**Security key**, then choose **Touch key** in the panel to approve the displayed
request. Windows may also prompt for a separate FIDO PIN.

**Unplug** in the panel locks the vault and detaches the virtual key. Removing
the physical drive also locks the session and disconnects the virtual key.
When moving the drive to another configured PC, launch with that PC's drive
letter and enter the same vault passphrase. The local DPAPI store and the portable
vault have independent registrations. If another emulator key is running, use
**Stop running key** in the panel before switching stores.

The drive needs only the `Fido2Emulator.vault` file. Initialization preserves the
drive's other files and refuses to replace an existing vault. Back up the vault
after adding or changing credentials, and keep a separate recovery method for your
accounts. The stored keys require the passphrase to recover. Lock the vault before
ejecting the drive to avoid interrupting a write.

For command-line use, run `python -m fido2_emulator plug --usb-drive E:` and use the
same `touch`, `status`, and `unplug` commands as for local mode.

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

To erase credentials and the PIN from the local Windows store, run:

```powershell
.\.venv\Scripts\python.exe -m fido2_emulator reset
```

Reset is destructive: existing website registrations can no longer authenticate
using this key. It does not delete the corresponding registrations on websites.
The reset replaces the local encrypted store without securely erasing its disk blocks.

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

Local runtime data defaults to `%LOCALAPPDATA%\Fido2Emulator`:

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

USB mode puts credential data, the signature counter, and FIDO PIN state in
`Fido2Emulator.vault` on the selected volume. It uses Argon2id for passphrase
derivation and AES-256-GCM for authenticated encryption. The control file and
lifecycle log stay in the local runtime directory.

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
