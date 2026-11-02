"""Small native control panel: attach, detach, and approve a pending touch."""

import threading
import tkinter as tk
from tkinter import messagebox, ttk

from .controller import Emulator


def run_gui():
    emulator = Emulator()
    root = tk.Tk()
    root.title("FIDO2 Development Key")
    root.geometry("480x310")
    root.resizable(False, False)
    root.configure(padx=24, pady=20)
    ttk.Label(root, text="FIDO2 Development Key", font=("Segoe UI", 19, "bold")).pack(anchor="w")
    ttk.Label(root, text="Python software authenticator · USB/IP", foreground="#555555").pack(
        anchor="w", pady=(4, 18)
    )
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

    ttk.Button(buttons, text="Plug in", command=lambda: action(emulator.plug)).pack(side="left")
    ttk.Button(buttons, text="Unplug", command=lambda: action(emulator.unplug)).pack(
        side="left", padx=8
    )
    touch = ttk.Button(buttons, text="Touch key", command=lambda: action(emulator.touch))
    touch.pack(side="left")
    ttk.Label(
        root,
        text="Approve only requests you initiated.\nClosing this panel leaves the key running.",
        foreground="#555555",
    ).pack(anchor="w", pady=(22, 0))

    def poll():
        state = emulator.status()
        status_label.config(
            text="Connected as USB security key" if state["connected"] else "Unplugged"
        )
        pending = state.get("pending")
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
