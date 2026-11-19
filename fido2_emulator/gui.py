"""Small native control panel: attach, detach, and approve a pending touch."""

import threading
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

from .controller import Emulator


def run_gui(usb_drive=None):
    emulator = Emulator()
    root = tk.Tk()
    root.title("FIDO2 Development Key")
    root.geometry("480x310")
    root.resizable(False, False)
    root.configure(padx=24, pady=20)
    ttk.Label(root, text="FIDO2 Development Key", font=("Segoe UI", 19, "bold")).pack(anchor="w")
    source = f"Encrypted vault on {usb_drive}" if usb_drive else "Windows user credential store"
    ttk.Label(root, text=source, foreground="#555555").pack(anchor="w", pady=(4, 18))
    status_label = ttk.Label(root, text="Checking device…", font=("Segoe UI", 11))
    status_label.pack(anchor="w")
    pending_label = ttk.Label(root, text="", wraplength=430, font=("Segoe UI", 11))
    pending_label.pack(anchor="w", pady=(12, 12))
    buttons = ttk.Frame(root)
    buttons.pack(anchor="w")
    busy = False

    def action(operation):
        nonlocal busy
        if busy:
            return
        busy = True

        def worker():
            nonlocal busy
            try:
                operation()
            except Exception as error:
                message = str(error)
                root.after(0, lambda: messagebox.showerror("FIDO2 emulator", message))
            finally:
                busy = False

        threading.Thread(target=worker, daemon=True).start()

    def plug_key():
        if busy:
            return
        if not usb_drive or emulator.status()["running"]:
            action(lambda: emulator.plug(usb_drive))
            return
        passphrase = simpledialog.askstring(
            "Unlock USB passkey vault", f"Passphrase for {usb_drive}", show="*", parent=root
        )
        if passphrase is not None:
            action(lambda: emulator.plug(usb_drive, lambda: passphrase))

    plug = ttk.Button(buttons, text="Plug in", command=plug_key)
    plug.pack(side="left")
    unplug = ttk.Button(buttons, text="Unplug")
    unplug.pack(side="left", padx=8)
    touch = ttk.Button(buttons, text="Touch key", command=lambda: action(emulator.touch))
    touch.pack(side="left")
    ttk.Label(
        root,
        text=(
            "Unplug the virtual key or remove the drive to lock its vault."
            if usb_drive
            else "Approve only requests you initiated.\nClosing this panel leaves the key running."
        ),
        foreground="#555555",
    ).pack(anchor="w", pady=(22, 0))

    def poll():
        state = emulator.status()
        other_key = state["running"] and state.get("usb_drive") != usb_drive
        label = "Connected as USB security key" if state["connected"] else "Unplugged"
        if other_key:
            label = "A different key is running"
        elif usb_drive and not state["running"]:
            label = "USB vault locked"
        status_label.config(text=label)
        plug.config(state="disabled" if other_key or busy else "normal")
        unplug.config(
            text="Stop running key" if other_key else "Unplug",
            command=lambda: action(emulator.stop if other_key else emulator.unplug),
            state="normal" if state["running"] and not busy else "disabled",
        )
        pending = None if other_key else state.get("pending")
        pending_label.config(
            text=(
                f"{pending['operation']}: {pending['rp']}"
                if pending
                else "No touch request pending."
            )
        )
        touch.config(state="normal" if pending and not busy else "disabled")
        root.after(500, poll)

    poll()
    root.mainloop()
