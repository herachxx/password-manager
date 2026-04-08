# gui.py - Tkinter GUI for PassWord Manager
# Part 2 of 2: GUI edition - shares crypto/vault/tools core with CLI unchanged
import hashlib
import os
import sys
import threading
import tkinter as tk
import tkinter.filedialog as filedialog
import tkinter.messagebox as msgbox
import tkinter.ttk as ttk
from constants import (
    LOCKOUT_DURATION,
    LOCKOUT_FILE,
    MAX_LOGIN_ATTEMPTS,
    MIN_GEN_LENGTH,
    MAX_GEN_LENGTH,
    DEFAULT_GEN_LENGTH,
    DEFAULT_VAULT_NAME,
    MIN_MASTER_LENGTH,
    PASSWORD_AGE_WARN,
    SESSION_TIMEOUT_SEC,
    VaultTamperedError,
    current_timestamp,
    format_timestamp,
    secure_random_bytes,
    strength_label,
    zero_bytes,
)
from crypto import derive_key
from tools import (
    SHA256_HASHES_PER_SEC,
    PBKDF2_HASHES_PER_SEC,
    _simulate_crack_time,
    generate_password,
    password_entropy,
)
from vault import (
    add_entry,
    delete_entry,
    find_entries,
    get_duplicate_passwords,
    get_old_passwords,
    get_salt,
    init_vault,
    list_entries,
    load_vault,
    log_event,
    read_log,
    save_vault,
    update_entry,
    vault_exists,
)
BG          = "#0f1117"   # Root background
BG_CARD     = "#1a1d27"   # Card / panel surface
BG_INPUT    = "#12151e"   # Input field background
BG_HOVER    = "#22263a"   # Button hover
BG_SELECTED = "#1e3a5f"   # Active list row
ACCENT      = "#4f8ef7"   # Primary blue
ACCENT_DIM  = "#2a4a8a"   # Dimmed blue (inactive borders)
SUCCESS     = "#22c55e"   # Green
WARNING     = "#f59e0b"   # Amber
DANGER      = "#ef4444"   # Red
INFO        = "#38bdf8"   # Sky blue
FG          = "#e2e8f0"   # Primary text
FG_DIM      = "#64748b"   # Secondary / placeholder
FG_MUTED    = "#334155"   # Disabled / separator label
BORDER      = "#1e2235"   # Subtle border / divider
STRENGTH_COLOR: dict[str, str] = {
    "Very Weak":   DANGER,
    "Weak":        DANGER,
    "Fair":        WARNING,
    "Strong":      SUCCESS,
    "Very Strong": SUCCESS,
    "Excellent":   INFO,
}
_WIN = sys.platform == "win32"
_MAC = sys.platform == "darwin"
FONT_UI = "Segoe UI"   if _WIN else ("SF Pro Display" if _MAC else "Ubuntu")
FONT_MONO = "Consolas"   if _WIN else ("SF Mono"        if _MAC else "Ubuntu Mono")
PAD = 16
PAD_SM =  8
PAD_XS =  4
def _entry(parent: tk.Widget, *, show: str = "", width: int = 30,
           size: int = 11) -> tk.Entry:
    """Dark-themed Entry widget."""
    return tk.Entry(
        parent,
        show=show, width=width,
        bg=BG_INPUT, fg=FG,
        insertbackground=ACCENT,
        selectbackground=ACCENT_DIM, selectforeground=FG,
        relief="flat", bd=0,
        highlightthickness=1,
        highlightbackground=BORDER, highlightcolor=ACCENT,
        font=(FONT_UI, size),
    )
def _button(parent: tk.Widget, text: str, command,
            kind: str = "primary") -> tk.Button:
    """
    Styled Button.

    kind values:
      "primary" - filled blue, white text
      "danger"  - filled red, white text
      "ghost"   - transparent surface, dim text
    """
    palette = {
        "primary": (ACCENT,  "#ffffff", ACCENT_DIM),
        "danger":  (DANGER,  "#ffffff", DANGER),
        "ghost":   (BG_CARD, FG_DIM,   BG_HOVER),
    }
    bg, fg, active_bg = palette.get(kind, palette["primary"])
    return tk.Button(
        parent,
        text=text, command=command,
        bg=bg, fg=fg,
        activebackground=active_bg, activeforeground=fg,
        relief="flat", bd=0,
        padx=PAD, pady=PAD_SM,
        cursor="hand2",
        font=(FONT_UI, 10, "bold"),
    )
def _label(parent: tk.Widget, text: str, *,
           size: int = 11, bold: bool = False,
           color: str = FG, mono: bool = False) -> tk.Label:
    """Convenience Label with sensible defaults."""
    return tk.Label(
        parent,
        text=text,
        bg=parent.cget("bg"),
        fg=color,
        font=(FONT_MONO if mono else FONT_UI, size,
              "bold" if bold else "normal"),
    )
def _separator(parent: tk.Widget) -> tk.Frame:
    """Single-pixel horizontal rule."""
    return tk.Frame(parent, bg=BORDER, height=1)
def _card(parent: tk.Widget, **kw) -> tk.Frame:
    """BG_CARD-coloured frame used as a visual card."""
    return tk.Frame(parent, bg=BG_CARD, **kw)
class _ScrolledText:
    """
    Read-only dark Text widget paired with a Scrollbar, wrapped in a Frame.

    Usage:
        st = _ScrolledText(parent, height=20)
        st.frame.pack(...)
        st.write("hello\\n")
        st.write("world\\n", tag="green")
    """
    def __init__(self, parent: tk.Widget, *, height: int = 12,
                 font_size: int = 9) -> None:
        self.frame = tk.Frame(parent, bg=BG_CARD)
        sb = tk.Scrollbar(self.frame, bg=BG_CARD, troughcolor=BG, relief="flat")
        self._txt = tk.Text(
            self.frame,
            height=height,
            bg=BG_INPUT, fg=FG,
            insertbackground=ACCENT,
            selectbackground=ACCENT_DIM,
            relief="flat", bd=0,
            padx=PAD_SM, pady=PAD_SM,
            font=(FONT_MONO, font_size),
            yscrollcommand=sb.set,
            state="disabled",
            wrap="word",
        )
        sb.config(command=self._txt.yview)
        sb.pack(side="right", fill="y")
        self._txt.pack(side="left", fill="both", expand=True)
    def tag(self, name: str, **kw) -> None:
        """Configure a named text tag."""
        self._txt.tag_configure(name, **kw)
    def write(self, text: str, tag: str | None = None) -> None:
        """Append text, optionally styled with a named tag."""
        self._txt.config(state="normal")
        self._txt.insert("end", text, (tag,) if tag else ())
        self._txt.see("end")
        self._txt.config(state="disabled")
    def clear(self) -> None:
        """Erase all content."""
        self._txt.config(state="normal")
        self._txt.delete("1.0", "end")
        self._txt.config(state="disabled")
def _read_lockout() -> tuple[int, int]:
    """Return (attempt_count, last_attempt_timestamp)."""
    if not os.path.exists(LOCKOUT_FILE):
        return 0, 0
    try:
        with open(LOCKOUT_FILE) as fh:
            parts = fh.read().strip().split()
        return int(parts[0]), int(parts[1])
    except (ValueError, IndexError, OSError):
        return 0, 0
def _write_lockout(attempts: int, ts: int) -> None:
    try:
        with open(LOCKOUT_FILE, "w") as fh:
            fh.write(f"{attempts} {ts}\n")
    except OSError:
        pass
def _clear_lockout() -> None:
    try:
        os.remove(LOCKOUT_FILE)
    except OSError:
        pass
def _lockout_seconds_remaining() -> int:
    """Return seconds left in lockout, or 0 if not locked out."""
    attempts, last = _read_lockout()
    if attempts < MAX_LOGIN_ATTEMPTS:
        return 0
    remaining = LOCKOUT_DURATION - (current_timestamp() - last)
    if remaining > 0:
        return int(remaining)
    _clear_lockout()
    return 0
def _validate_master_password(pw: str) -> str | None:
    """
    Enforce the master password policy.
    Returns an error string, or None when the password is acceptable.
    """
    if len(pw) < MIN_MASTER_LENGTH:
        return f"Must be at least {MIN_MASTER_LENGTH} characters."
    if not any(c.isupper() for c in pw):
        return "Must contain at least one uppercase letter."
    if not any(c.isdigit() for c in pw):
        return "Must contain at least one digit."
    return None
class Session:
    """
    Active vault session.

    The AES key lives in a ``bytearray`` so it can be explicitly zeroed
    when the vault locks or closes, reducing the window during which a
    memory dump could recover key material.
    """
    def __init__(self, key_buf: bytearray, payload: dict,
                 vault_path: str) -> None:
        self.key_buf = key_buf
        self.payload = payload
        self.vault_path = vault_path
        self.last_activity = current_timestamp()
        self.locked = False
    def touch(self) -> None:
        """Reset the idle timer. Call on every user action."""
        self.last_activity = current_timestamp()
    def idle_seconds(self) -> int:
        """Seconds since the last user action."""
        return current_timestamp() - self.last_activity
    def save(self) -> None:
        """Re-encrypt and write the vault to disk."""
        save_vault(self.vault_path, self.payload, bytes(self.key_buf))
        log_event("VAULT_SAVED")
    def lock(self) -> None:
        """Zero the key and mark the session locked."""
        zero_bytes(self.key_buf)
        self.locked = True
        log_event("SESSION_LOCKED")
    def close(self) -> None:
        """Lock and log closure (called on window close)."""
        self.lock()
        log_event("SESSION_CLOSED")
class LoginFrame(tk.Frame):
    """
    Shown at startup and after the vault locks.

    Responsibilities:
      · Browse for or type a vault path
      · Switch between "unlock" mode (existing vault) and "create" mode
      · Run PBKDF2 key derivation in a daemon thread (never blocks the UI)
      · Enforce login lockout and display attempt count
    """
    def __init__(self, master: tk.Widget, on_success) -> None:
        super().__init__(master, bg=BG)
        self._on_success = on_success
        self._vault_path = tk.StringVar(value=DEFAULT_VAULT_NAME)
        self._is_new = False
        self._working = False
        self._build()
        self._refresh_mode()
    def _build(self) -> None:
        outer = tk.Frame(self, bg=BG)
        outer.place(relx=0.5, rely=0.5, anchor="center")
        tk.Label(outer, text="🔐  PassWord", bg=BG, fg=ACCENT,
                 font=(FONT_UI, 28, "bold")).pack(pady=(0, 4))
        tk.Label(outer, text="AES-256 · PBKDF2-SHA256 · HMAC-SHA256",
                 bg=BG, fg=FG_DIM, font=(FONT_UI, 9)).pack(pady=(0, PAD * 2))
        card = _card(outer)
        card.pack(ipadx=PAD * 2, ipady=PAD * 2)
        _label(card, "Vault file", size=9, color=FG_DIM).pack(
            anchor="w", padx=PAD, pady=(PAD, 0))
        path_row = tk.Frame(card, bg=BG_CARD)
        path_row.pack(fill="x", padx=PAD, pady=(0, PAD_SM))
        self._path_entry = _entry(path_row, width=32, size=10)
        self._path_entry.insert(0, DEFAULT_VAULT_NAME)
        self._path_entry.pack(side="left", fill="x", expand=True)
        self._path_entry.bind("<FocusOut>", lambda _e: self._refresh_mode())
        self._path_entry.bind("<Return>",   lambda _e: self._refresh_mode())
        tk.Button(
            path_row, text="Browse", command=self._browse,
            bg=BG_INPUT, fg=FG_DIM, activebackground=BG_HOVER,
            relief="flat", bd=0, padx=PAD_SM, cursor="hand2",
            font=(FONT_UI, 9),
        ).pack(side="left", padx=(PAD_XS, 0))
        self._mode_lbl = tk.Label(card, text="", bg=BG_CARD,
                                   fg=INFO, font=(FONT_UI, 9, "italic"))
        self._mode_lbl.pack(pady=(0, PAD_SM))
        _label(card, "Master password", size=9, color=FG_DIM).pack(
            anchor="w", padx=PAD)
        self._pw_entry = _entry(card, show="●", width=36, size=12)
        self._pw_entry.pack(padx=PAD, pady=(0, PAD_SM), fill="x")
        self._pw_entry.bind("<Return>", lambda _e: self._submit())
        self._pw_entry.bind("<KeyRelease>", self._on_pw_key)
        self._confirm_lbl   = _label(card, "Confirm password", size=9, color=FG_DIM)
        self._confirm_entry = _entry(card, show="●", width=36, size=12)
        self._confirm_entry.bind("<Return>", lambda _e: self._submit())
        self._strength_frame  = tk.Frame(card, bg=BG_CARD)
        self._strength_canvas = tk.Canvas(self._strength_frame, height=6,
                                           bg=BG_INPUT, highlightthickness=0)
        self._strength_canvas.pack(fill="x", padx=PAD, pady=(0, PAD_XS))
        self._strength_lbl = tk.Label(self._strength_frame, text="",
                                       bg=BG_CARD, fg=FG_DIM,
                                       font=(FONT_UI, 8))
        self._strength_lbl.pack(anchor="w", padx=PAD)
        self._error_lbl = tk.Label(card, text="", bg=BG_CARD, fg=DANGER,
                                    font=(FONT_UI, 9), wraplength=320)
        self._error_lbl.pack(pady=(0, PAD_SM))
        self._attempts_lbl = tk.Label(card, text="", bg=BG_CARD, fg=WARNING,
                                       font=(FONT_UI, 9))
        self._attempts_lbl.pack()
        self._submit_btn = _button(card, "Unlock Vault", self._submit)
        self._submit_btn.pack(pady=(PAD_SM, PAD), fill="x", padx=PAD)
        self._progress = ttk.Progressbar(card, mode="indeterminate", length=320)
        _style = ttk.Style()
        _style.theme_use("default")
        _style.configure("Accent.Horizontal.TProgressbar",
                          troughcolor=BG_INPUT, background=ACCENT, thickness=4)
        self._progress.configure(style="Accent.Horizontal.TProgressbar")
    def _browse(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Choose or create vault file",
            defaultextension=".vault",
            filetypes=[("Vault files", "*.vault"), ("All files", "*.*")],
            initialfile=DEFAULT_VAULT_NAME,
        )
        if path:
            self._path_entry.delete(0, "end")
            self._path_entry.insert(0, path)
            self._refresh_mode()

    def _refresh_mode(self) -> None:
        """Switch UI between 'unlock existing' and 'create new' modes."""
        path = self._path_entry.get().strip()
        self._vault_path.set(path)
        self._is_new = not vault_exists(path)
        if self._is_new:
            self._mode_lbl.config(text="✦  New vault - choose a master password")
            self._submit_btn.config(text="Create Vault")
            self._confirm_lbl.pack(anchor="w", padx=PAD)
            self._confirm_entry.pack(padx=PAD, pady=(0, PAD_SM), fill="x")
            self._strength_frame.pack(fill="x", pady=(0, PAD_SM))
        else:
            self._mode_lbl.config(text="✓  Vault found - enter master password")
            self._submit_btn.config(text="Unlock Vault")
            self._confirm_lbl.pack_forget()
            self._confirm_entry.pack_forget()
            self._strength_frame.pack_forget()
        self._error_lbl.config(text="")
        self._refresh_attempts_label()
    def _on_pw_key(self, _event=None) -> None:
        """Update the live strength bar while typing (new vault mode only)."""
        if not self._is_new:
            return
        pw = self._pw_entry.get()
        if not pw:
            self._strength_canvas.delete("all")
            self._strength_lbl.config(text="")
            return
        bits = password_entropy(pw)
        lbl, _ = strength_label(bits)
        color = STRENGTH_COLOR.get(lbl, FG_DIM)
        w = self._strength_canvas.winfo_width() or 320
        self._strength_canvas.delete("all")
        self._strength_canvas.create_rectangle(
            0, 0, int(min(bits / 130.0, 1.0) * w), 6, fill=color, outline="")
        self._strength_lbl.config(
            text=f"{lbl}  ·  {bits:.0f} bits entropy", fg=color)
    def _refresh_attempts_label(self) -> None:
        attempts, _ = _read_lockout()
        if attempts > 0:
            rem = MAX_LOGIN_ATTEMPTS - attempts
            self._attempts_lbl.config(
                text=f"⚠  {attempts} failed attempt(s) - {rem} remaining")
        else:
            self._attempts_lbl.config(text="")
    def _set_error(self, msg: str) -> None:
        self._error_lbl.config(text=msg)
    def _set_working(self, working: bool) -> None:
        """Swap between idle UI and 'PBKDF2 running' UI."""
        self._working = working
        state = "disabled" if working else "normal"
        self._submit_btn.config(state=state)
        self._pw_entry.config(state=state)
        if working:
            self._progress.pack(padx=PAD, pady=(0, PAD), fill="x")
            self._progress.start(12)
        else:
            self._progress.stop()
            self._progress.pack_forget()
    def _submit(self) -> None:
        if self._working:
            return
        remaining = _lockout_seconds_remaining()
        if remaining > 0:
            self._set_error(f"Locked out. Try again in {remaining} seconds.")
            return
        path = self._vault_path.get().strip()
        if not path:
            self._set_error("Please choose a vault file.")
            return
        pw = self._pw_entry.get()
        if not pw:
            self._set_error("Please enter your master password.")
            return
        self._set_error("")
        if self._is_new:
            self._do_create(path, pw)
        else:
            self._do_unlock(path, pw)
    def _do_create(self, path: str, pw: str) -> None:
        err = _validate_master_password(pw)
        if err:
            self._set_error(err)
            return
        if pw != self._confirm_entry.get():
            self._set_error("Passwords do not match.")
            return
        self._set_working(True)
        def worker() -> None:
            try:
                salt = secure_random_bytes(32)
                key_buf = bytearray(derive_key(pw, salt))
                payload = init_vault(path, bytes(key_buf), salt=salt)
                log_event("VAULT_CREATED", path)
                session = Session(key_buf, payload, path)
                self.after(0, lambda: self._on_success(session))
            except Exception as exc:
                self.after(0, lambda: (
                    self._set_working(False),
                    self._set_error(f"Failed to create vault: {exc}"),
                ))
        threading.Thread(target=worker, daemon=True).start()
    def _do_unlock(self, path: str, pw: str) -> None:
        self._set_working(True)
        def worker() -> None:
            try:
                salt = get_salt(path)
                key_buf = bytearray(derive_key(pw, salt))
                payload = load_vault(path, bytes(key_buf))
                _clear_lockout()
                log_event("LOGIN_SUCCESS")
                session = Session(key_buf, payload, path)
                self.after(0, lambda: self._on_success(session))
            except VaultTamperedError:
                attempts, _ = _read_lockout()
                _write_lockout(attempts + 1, current_timestamp())
                log_event("LOGIN_FAILED", "HMAC verification failed")
                self.after(0, lambda: (
                    self._set_working(False),
                    self._set_error("Wrong password or vault tampered."),
                    self._refresh_attempts_label(),
                ))
            except Exception:
                attempts, _ = _read_lockout()
                _write_lockout(attempts + 1, current_timestamp())
                log_event("LOGIN_FAILED", "Wrong password")
                self.after(0, lambda: (
                    self._set_working(False),
                    self._set_error("Incorrect master password."),
                    self._refresh_attempts_label(),
                ))
        threading.Thread(target=worker, daemon=True).start()
class VaultView(tk.Frame):
    """
    Searchable, scrollable list of credentials.

    Each entry renders as a collapsed card showing site + strength label.
    Clicking the card expands an inline detail panel with username,
    masked password, Show/Hide toggle, one-click Copy, entropy bar,
    notes, and Edit / Delete buttons.
    """
    def __init__(self, master: tk.Widget, session: Session,
                 on_edit, on_delete) -> None:
        super().__init__(master, bg=BG)
        self._session = session
        self._on_edit = on_edit
        self._on_delete = on_delete
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._refresh())
        self._build()
        self._refresh()
    def _build(self) -> None:
        top = tk.Frame(self, bg=BG)
        top.pack(fill="x", padx=PAD, pady=(PAD, 0))
        _label(top, "Credentials", size=16, bold=True).pack(side="left")
        tk.Label(top, text="🔍", bg=BG, fg=FG_DIM,
                 font=(FONT_UI, 12)).pack(side="right", padx=PAD_XS)
        search = _entry(top, width=22, size=10)
        search.configure(textvariable=self._search_var)
        search.pack(side="right")
        _separator(self).pack(fill="x", padx=PAD, pady=PAD_SM)
        container = tk.Frame(self, bg=BG)
        container.pack(fill="both", expand=True, padx=PAD)
        sb = tk.Scrollbar(container, bg=BG, troughcolor=BG, relief="flat")
        sb.pack(side="right", fill="y")
        self._canvas = tk.Canvas(container, bg=BG,
                                  highlightthickness=0,
                                  yscrollcommand=sb.set)
        self._canvas.pack(side="left", fill="both", expand=True)
        sb.config(command=self._canvas.yview)
        self._list_frame = tk.Frame(self._canvas, bg=BG)
        self._win_id = self._canvas.create_window(
            (0, 0), window=self._list_frame, anchor="nw")
        self._list_frame.bind(
            "<Configure>",
            lambda _e: self._canvas.configure(
                scrollregion=self._canvas.bbox("all")))
        self._canvas.bind(
            "<Configure>",
            lambda e: self._canvas.itemconfig(self._win_id, width=e.width))
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self._canvas.bind_all(seq, self._on_scroll)
        self.bind("<Destroy>", self._on_destroy)
    def _on_destroy(self, _event: tk.Event) -> None:
        """Remove global scroll bindings so they don't fire on a dead canvas."""
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            try:
                self._canvas.unbind_all(seq)
            except Exception:
                pass
    def _on_scroll(self, event: tk.Event) -> None:
        try:
            if event.num == 4:
                self._canvas.yview_scroll(-1, "units")
            elif event.num == 5:
                self._canvas.yview_scroll(1, "units")
            else:
                self._canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        except tk.TclError:
            pass
    def refresh(self) -> None:
        self._refresh()
    def _refresh(self) -> None:
        query   = self._search_var.get().strip()
        entries = (find_entries(self._session.payload, query) if query
                   else list_entries(self._session.payload))
        for w in self._list_frame.winfo_children():
            w.destroy()
        if not entries:
            msg = ("No entries match your search." if query
                   else "No credentials yet - click Add Entry.")
            tk.Label(self._list_frame, text=msg, bg=BG, fg=FG_DIM,
                     font=(FONT_UI, 11)).pack(pady=PAD * 3)
            return
        for entry in entries:
            self._build_card(entry)
    def _build_card(self, entry: dict) -> None:
        """Single collapsible credential card."""
        bits = password_entropy(entry["password"])
        lbl, _ = strength_label(bits)
        strength_color = STRENGTH_COLOR.get(lbl, FG_DIM)
        card = tk.Frame(self._list_frame, bg=BG_CARD, cursor="hand2")
        card.pack(fill="x", pady=(0, PAD_XS))
        header = tk.Frame(card, bg=BG_CARD)
        header.pack(fill="x", padx=PAD, pady=PAD_SM)
        site_lbl = tk.Label(header, text=entry["site"], bg=BG_CARD, fg=FG,
                             font=(FONT_UI, 12, "bold"))
        site_lbl.pack(side="left")
        tk.Label(header, text=f"  {lbl}", bg=BG_CARD, fg=strength_color,
                 font=(FONT_UI, 9)).pack(side="left")
        tk.Label(header, text=entry["username"], bg=BG_CARD, fg=FG_DIM,
                 font=(FONT_UI, 9)).pack(side="right")
        detail = tk.Frame(card, bg=BG_CARD)
        _separator(detail).pack(fill="x")
        inner = tk.Frame(detail, bg=BG_CARD)
        inner.pack(fill="x", padx=PAD, pady=PAD_SM)
        _label(inner, "Username", size=8, color=FG_DIM).grid(
            row=0, column=0, sticky="w", pady=PAD_XS)
        tk.Label(inner, text=entry["username"], bg=BG_CARD, fg=FG,
                 font=(FONT_UI, 10)).grid(row=0, column=1, sticky="w",
                                          padx=PAD_SM)
        _label(inner, "Password", size=8, color=FG_DIM).grid(
            row=1, column=0, sticky="w", pady=PAD_XS)
        pw_var = tk.StringVar(value="●" * min(len(entry["password"]), 20))
        tk.Label(inner, textvariable=pw_var, bg=BG_CARD, fg=FG,
                 font=(FONT_MONO, 10)).grid(row=1, column=1, sticky="w",
                                             padx=PAD_SM)
        revealed = [False]
        small = dict(bg=BG_INPUT, fg=FG_DIM, activebackground=BG_HOVER,
                     relief="flat", bd=0, padx=PAD_SM, cursor="hand2",
                     font=(FONT_UI, 8))
        def toggle_reveal() -> None:
            revealed[0] = not revealed[0]
            pw_var.set(entry["password"] if revealed[0]
                       else "●" * min(len(entry["password"]), 20))
            reveal_btn.config(text="Hide" if revealed[0] else "Show")
        def copy_pw() -> None:
            self.clipboard_clear()
            self.clipboard_append(entry["password"])
            copy_btn.config(text="Copied!", fg=SUCCESS)
            self.after(1500, lambda: copy_btn.config(text="Copy", fg=FG_DIM))
        reveal_btn = tk.Button(inner, text="Show", command=toggle_reveal, **small)
        copy_btn   = tk.Button(inner, text="Copy", command=copy_pw,       **small)
        reveal_btn.grid(row=1, column=2, padx=PAD_XS)
        copy_btn.grid(  row=1, column=3, padx=PAD_XS)
        _label(inner, "Strength", size=8, color=FG_DIM).grid(
            row=2, column=0, sticky="w", pady=PAD_XS)
        bar_frame  = tk.Frame(inner, bg=BG_CARD)
        bar_frame.grid(row=2, column=1, columnspan=3, sticky="w", padx=PAD_SM)
        bar_canvas = tk.Canvas(bar_frame, width=160, height=6,
                                bg=BG_INPUT, highlightthickness=0)
        bar_canvas.pack(side="left")
        bar_canvas.create_rectangle(
            0, 0, int(min(bits / 130.0, 1.0) * 160), 6,
            fill=strength_color, outline="")
        tk.Label(bar_frame, text=f"  {bits:.0f} bits",
                 bg=BG_CARD, fg=strength_color,
                 font=(FONT_UI, 8)).pack(side="left")
        if entry.get("notes"):
            _label(inner, "Notes", size=8, color=FG_DIM).grid(
                row=3, column=0, sticky="nw", pady=PAD_XS)
            tk.Label(inner, text=entry["notes"], bg=BG_CARD, fg=FG_DIM,
                     font=(FONT_UI, 9), wraplength=300,
                     justify="left").grid(row=3, column=1, columnspan=3,
                                          sticky="w", padx=PAD_SM)
        _label(inner, "Modified", size=8, color=FG_DIM).grid(
            row=4, column=0, sticky="w", pady=PAD_XS)
        tk.Label(inner, text=format_timestamp(entry["modified"]),
                 bg=BG_CARD, fg=FG_DIM,
                 font=(FONT_UI, 8)).grid(row=4, column=1, sticky="w",
                                          padx=PAD_SM)
        actions = tk.Frame(detail, bg=BG_CARD)
        actions.pack(fill="x", padx=PAD, pady=(0, PAD_SM))
        _button(actions, "Edit",
                lambda e=entry: self._on_edit(e), kind="ghost").pack(
            side="left", padx=(0, PAD_XS))
        _button(actions, "Delete",
                lambda e=entry: self._on_delete(e), kind="danger").pack(
            side="left")
        expanded = [False]
        def toggle(_event=None) -> None:
            expanded[0] = not expanded[0]
            bg = BG_SELECTED if expanded[0] else BG_CARD
            if expanded[0]:
                detail.pack(fill="x")
            else:
                detail.pack_forget()
            for w in (card, header, site_lbl):
                w.config(bg=bg)
        for w in (card, header, site_lbl):
            w.bind("<Button-1>", toggle)
class AddEditView(tk.Frame):
    """
    Credential form - serves both "Add" and "Edit" modes.

    In edit mode, ``entry`` is the existing credential dict and all fields
    are pre-populated.  In add mode, ``entry`` is None.
    """
    def __init__(self, master: tk.Widget, session: Session,
                 on_save, on_cancel, entry: dict | None = None) -> None:
        super().__init__(master, bg=BG)
        self._session = session
        self._on_save = on_save
        self._on_cancel = on_cancel
        self._entry = entry
        self._pw_visible = False
        self._build()
    def _build(self) -> None:
        title = "Edit Credential" if self._entry else "Add Credential"
        _label(self, title, size=16, bold=True).pack(
            anchor="w", padx=PAD, pady=(PAD, PAD_SM))
        _separator(self).pack(fill="x", padx=PAD, pady=PAD_SM)
        form = _card(self)
        form.pack(fill="x", padx=PAD, pady=PAD_SM, ipadx=PAD, ipady=PAD)
        form.columnconfigure(0, weight=1)
        def text_field(label_text: str, grid_row: int) -> tk.Entry:
            _label(form, label_text, size=9, color=FG_DIM).grid(
                row=grid_row * 2, column=0, columnspan=2,
                sticky="w", padx=PAD, pady=(PAD_SM, 0))
            e = _entry(form, width=40)
            e.grid(row=grid_row * 2 + 1, column=0, columnspan=2,
                   padx=PAD, pady=(0, PAD_SM), sticky="ew")
            return e
        self._site_e = text_field("Site / Service",  0)
        self._user_e = text_field("Username / Email", 1)
        _label(form, "Password", size=9, color=FG_DIM).grid(
            row=4, column=0, sticky="w", padx=PAD, pady=(PAD_SM, 0))
        pw_row = tk.Frame(form, bg=BG_CARD)
        pw_row.grid(row=5, column=0, columnspan=2, sticky="ew",
                    padx=PAD, pady=(0, PAD_SM))
        pw_row.columnconfigure(0, weight=1)
        self._pw_entry = _entry(pw_row, show="●", width=30)
        self._pw_entry.grid(row=0, column=0, sticky="ew")
        self._pw_entry.bind("<KeyRelease>", self._update_strength)
        small = dict(bg=BG_INPUT, fg=FG_DIM, activebackground=BG_HOVER,
                     relief="flat", bd=0, padx=PAD_SM, cursor="hand2",
                     font=(FONT_UI, 8))
        def toggle_vis() -> None:
            self._pw_visible = not self._pw_visible
            self._pw_entry.config(show="" if self._pw_visible else "●")
            vis_btn.config(text="Hide" if self._pw_visible else "Show")
        vis_btn = tk.Button(pw_row, text="Show", command=toggle_vis, **small)
        vis_btn.grid(row=0, column=1, padx=PAD_XS)
        tk.Button(pw_row, text="Generate", command=self._generate,
                  bg=ACCENT_DIM, fg=FG, activebackground=ACCENT,
                  relief="flat", bd=0, padx=PAD_SM, cursor="hand2",
                  font=(FONT_UI, 8)).grid(row=0, column=2)
        self._strength_canvas = tk.Canvas(form, height=4,
                                           bg=BG_INPUT, highlightthickness=0)
        self._strength_canvas.grid(row=6, column=0, columnspan=2,
                                    sticky="ew", padx=PAD, pady=(0, PAD_XS))
        self._strength_lbl = tk.Label(form, text="", bg=BG_CARD, fg=FG_DIM,
                                       font=(FONT_UI, 8))
        self._strength_lbl.grid(row=7, column=0, sticky="w", padx=PAD)
        self._notes_e = text_field("Notes (optional)", 4)
        if self._entry:
            self._site_e.insert(0, self._entry["site"])
            self._user_e.insert(0, self._entry["username"])
            self._pw_entry.insert(0, self._entry["password"])
            if self._entry.get("notes"):
                self._notes_e.insert(0, self._entry["notes"])
            self._update_strength()
        btn_row = tk.Frame(self, bg=BG)
        btn_row.pack(padx=PAD, pady=PAD, anchor="w")
        _button(btn_row, "Save",   self._save).pack(side="left", padx=(0, PAD_SM))
        _button(btn_row, "Cancel", self._on_cancel, kind="ghost").pack(side="left")
    def _generate(self) -> None:
        pw = generate_password(DEFAULT_GEN_LENGTH)
        self._pw_entry.delete(0, "end")
        self._pw_entry.insert(0, pw)
        self._update_strength()
    def _update_strength(self, _event=None) -> None:
        pw = self._pw_entry.get()
        if not pw:
            self._strength_canvas.delete("all")
            self._strength_lbl.config(text="")
            return
        bits = password_entropy(pw)
        lbl, _ = strength_label(bits)
        color = STRENGTH_COLOR.get(lbl, FG_DIM)
        w = self._strength_canvas.winfo_width() or 400
        self._strength_canvas.delete("all")
        self._strength_canvas.create_rectangle(
            0, 0, int(min(bits / 130.0, 1.0) * w), 4, fill=color, outline="")
        self._strength_lbl.config(text=f"{lbl}  ·  {bits:.0f} bits", fg=color)

    def _save(self) -> None:
        site = self._site_e.get().strip()
        user = self._user_e.get().strip()
        pw = self._pw_entry.get()
        notes = self._notes_e.get().strip()
        for value, msg in [
            (site, "Site / Service is required."),
            (user, "Username is required."),
            (pw, "Password is required."),
        ]:
            if not value:
                msgbox.showerror("Missing field", msg)
                return
        if self._entry:
            update_entry(self._session.payload, self._entry["id"],
                         site=site, username=user, password=pw, notes=notes)
            log_event("ENTRY_UPDATED", str(self._entry["id"]))
        else:
            add_entry(self._session.payload, site, user, pw, notes)
            log_event("ENTRY_ADDED", site)
        self._session.save()
        self._on_save()
class GeneratorView(tk.Frame):
    """
    Standalone password generator.

    Controls: length slider, character-set checkboxes, safe-mode toggle.
    Output: generated password, live entropy bar, Regenerate and Copy buttons.
    """
    def __init__(self, master: tk.Widget) -> None:
        super().__init__(master, bg=BG)
        self._length_var = tk.IntVar(value=DEFAULT_GEN_LENGTH)
        self._upper_var = tk.BooleanVar(value=True)
        self._digits_var = tk.BooleanVar(value=True)
        self._symbols_var = tk.BooleanVar(value=True)
        self._safe_var = tk.BooleanVar(value=False)
        self._result_var = tk.StringVar()
        self._build()
        self._generate()
    def _build(self) -> None:
        _label(self, "Password Generator", size=16, bold=True).pack(
            anchor="w", padx=PAD, pady=(PAD, PAD_SM))
        _separator(self).pack(fill="x", padx=PAD, pady=PAD_SM)
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=PAD)
        opts = _card(body)
        opts.pack(fill="x", pady=(0, PAD))
        len_row = tk.Frame(opts, bg=BG_CARD)
        len_row.pack(fill="x", padx=PAD, pady=PAD)
        _label(len_row, "Length:", color=FG_DIM).pack(side="left")
        tk.Label(len_row, textvariable=self._length_var, bg=BG_CARD, fg=ACCENT,
                 font=(FONT_UI, 12, "bold"), width=3).pack(side="left", padx=PAD_SM)
        tk.Scale(opts, variable=self._length_var,
                 from_=MIN_GEN_LENGTH, to=MAX_GEN_LENGTH,
                 orient="horizontal", showvalue=False,
                 bg=BG_CARD, fg=FG, highlightthickness=0,
                 troughcolor=BG_INPUT, activebackground=ACCENT,
                 command=lambda _: self._generate()).pack(
            fill="x", padx=PAD, pady=(0, PAD_SM))
        cb_kw = dict(bg=BG_CARD, fg=FG, selectcolor=BG_INPUT,
                     activebackground=BG_CARD, activeforeground=FG,
                     font=(FONT_UI, 10), cursor="hand2",
                     command=self._generate)
        for text, var in [
            ("Uppercase letters (A–Z)", self._upper_var),
            ("Digits (0–9)", self._digits_var),
            ("Symbols (!@#$...)", self._symbols_var),
            ("Safe mode - no ambiguous characters (l 1 O 0 I)", self._safe_var),
        ]:
            tk.Checkbutton(opts, text=text, variable=var,
                           **cb_kw).pack(anchor="w", padx=PAD, pady=PAD_XS)
        res = _card(body)
        res.pack(fill="x", pady=(0, PAD))
        tk.Label(res, textvariable=self._result_var, bg=BG_CARD, fg=FG,
                 font=(FONT_MONO, 15, "bold"),
                 wraplength=500, justify="center",
                 pady=PAD).pack(fill="x", padx=PAD)
        self._bar = tk.Canvas(res, height=8, bg=BG_INPUT, highlightthickness=0)
        self._bar.pack(fill="x", padx=PAD, pady=(0, PAD_XS))
        self._str_lbl = tk.Label(res, text="", bg=BG_CARD, fg=FG_DIM,
                                  font=(FONT_UI, 9))
        self._str_lbl.pack(pady=(0, PAD_SM))
        btn_row = tk.Frame(res, bg=BG_CARD)
        btn_row.pack(pady=(0, PAD))
        _button(btn_row, "🔄  Regenerate", self._generate).pack(
            side="left", padx=(PAD, PAD_SM))
        _button(btn_row, "📋  Copy", self._copy, kind="ghost").pack(side="left")
    def _generate(self, _=None) -> None:
        try:
            pw = generate_password(
                length      = self._length_var.get(),
                use_upper   = self._upper_var.get(),
                use_digits  = self._digits_var.get(),
                use_symbols = self._symbols_var.get(),
                safe_mode   = self._safe_var.get(),
            )
        except ValueError as exc:
            self._result_var.set(str(exc))
            return
        self._result_var.set(pw)
        bits = password_entropy(pw)
        lbl, _ = strength_label(bits)
        color = STRENGTH_COLOR.get(lbl, FG_DIM)
        self._bar.update_idletasks()
        w = self._bar.winfo_width() or 500
        self._bar.delete("all")
        self._bar.create_rectangle(
            0, 0, int(min(bits / 130.0, 1.0) * w), 8, fill=color, outline="")
        self._str_lbl.config(
            text=f"{lbl}  ·  {bits:.0f} bits  ·  {len(pw)} characters",
            fg=color)
    def _copy(self) -> None:
        pw = self._result_var.get()
        if pw:
            self.clipboard_clear()
            self.clipboard_append(pw)
class AuditView(tk.Frame):
    """
    Full vault security audit covering:
      · Password reuse across multiple sites
      · Passwords not updated within PASSWORD_AGE_WARN days
      · Passwords below 60 bits of entropy
      · Bruteforce time estimates (SHA-256 vs PBKDF2-600k)
    """
    def __init__(self, master: tk.Widget, session: Session) -> None:
        super().__init__(master, bg=BG)
        self._session = session
        self._build()
    def _build(self) -> None:
        _label(self, "Security Audit", size=16, bold=True).pack(
            anchor="w", padx=PAD, pady=(PAD, PAD_SM))
        _separator(self).pack(fill="x", padx=PAD, pady=PAD_SM)
        entries = list_entries(self._session.payload)
        if not entries:
            tk.Label(self, text="Vault is empty - nothing to audit.",
                     bg=BG, fg=FG_DIM, font=(FONT_UI, 11)).pack(pady=PAD * 3)
            return
        st = _ScrolledText(self, height=30, font_size=10)
        st.frame.pack(fill="both", expand=True, padx=PAD, pady=PAD_SM)
        for name, kw in [
            ("heading", dict(foreground=ACCENT, font=(FONT_UI, 11, "bold"))),
            ("ok", dict(foreground=SUCCESS, font=(FONT_UI, 10))),
            ("warn", dict(foreground=WARNING, font=(FONT_UI, 10))),
            ("bad", dict(foreground=DANGER, font=(FONT_UI, 10))),
            ("dim", dict(foreground=FG_DIM, font=(FONT_UI, 9))),
            ("sep", dict(foreground=FG_MUTED, font=(FONT_MONO, 9))),
        ]:
            st.tag(name, **kw)
        w = st.write
        issues = 0
        w(f"Scanning {len(entries)} entries...\n\n", "dim")
        w("[ CHECK 1 ]  PASSWORD REUSE\n", "heading")
        dupes = get_duplicate_passwords(self._session.payload)
        if dupes:
            for group in dupes:
                w(f"  ⚠  Same password: {', '.join(e['site'] for e in group)}\n",
                  "warn")
                issues += 1
        else:
            w("  ✔  No password reuse detected.\n", "ok")
        w("─" * 60 + "\n", "sep")
        w(f"[ CHECK 2 ]  PASSWORD AGE  (>{PASSWORD_AGE_WARN} days)\n", "heading")
        old = get_old_passwords(self._session.payload, PASSWORD_AGE_WARN)
        if old:
            for e in old:
                w(f"  ⚠  {e['site']} ({e['username']}) - "
                  f"last changed {format_timestamp(e.get('modified', 0))}\n", "warn")
                issues += 1
        else:
            w(f"  ✔  All passwords changed within {PASSWORD_AGE_WARN} days.\n", "ok")
        w("─" * 60 + "\n", "sep")
        w("[ CHECK 3 ]  PASSWORD STRENGTH\n", "heading")
        weak = False
        for e in entries:
            bits = password_entropy(e["password"])
            lbl, _ = strength_label(bits)
            if bits < 60:
                w(f"  ⚠  {e['site']} ({e['username']}) - {lbl} ({bits:.0f} bits)\n",
                  "warn")
                issues += 1
                weak = True
        if not weak:
            w("  ✔  All passwords meet minimum strength requirements.\n", "ok")
        w("─" * 60 + "\n", "sep")
        w("[ INFO ]  BRUTEFORCE TIME ESTIMATES\n", "heading")
        w(f"  {'Site':<22} {'SHA-256':<22} {'PBKDF2-600k':<22} Bits\n", "dim")
        w("  " + "─" * 72 + "\n", "sep")
        for e in entries:
            bits = password_entropy(e["password"])
            sha_t = _simulate_crack_time(e["password"], SHA256_HASHES_PER_SEC)
            pbkdf_t = _simulate_crack_time(e["password"], PBKDF2_HASHES_PER_SEC)
            tag = "bad" if bits < 36 else "warn" if bits < 60 else "ok"
            w(f"  {e['site']:<22} {sha_t:<22} {pbkdf_t:<22} {bits:.0f}\n", tag)
        w("\n" + "─" * 60 + "\n", "sep")
        if issues == 0:
            w("  ✔  No issues found. Vault is in excellent shape.\n", "ok")
        else:
            w(f"  ⚠  {issues} issue(s) found. Review the warnings above.\n", "warn")
class HasherView(tk.Frame):
    """
    Interactive SHA-256 visualizer.

    The full compression - padding, message schedule W[0..63], all 64
    rounds with working variables a..h - streams into the output panel
    from a daemon thread via after() so the UI never freezes.

    The final digest is verified against hashlib.sha256 on every run.
    """
    _H0: list[int] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ]
    _K: list[int] = [
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
    ]
    def __init__(self, master: tk.Widget) -> None:
        super().__init__(master, bg=BG)
        self._running = False
        self._build()
    def _build(self) -> None:
        _label(self, "SHA-256 Visualizer", size=16, bold=True).pack(
            anchor="w", padx=PAD, pady=(PAD, PAD_SM))
        _separator(self).pack(fill="x", padx=PAD, pady=PAD_SM)
        top = tk.Frame(self, bg=BG)
        top.pack(fill="x", padx=PAD, pady=(0, PAD_SM))
        _label(top, "Input text:", color=FG_DIM).pack(side="left")
        self._input = _entry(top, width=36, size=11)
        self._input.pack(side="left", padx=PAD_SM, fill="x", expand=True)
        self._input.bind("<Return>", lambda _e: self._run())
        speed_frame = tk.Frame(top, bg=BG)
        speed_frame.pack(side="left", padx=PAD_SM)
        _label(speed_frame, "Speed:", color=FG_DIM).pack(side="left")
        self._speed = ttk.Combobox(speed_frame,
                                    values=["Fast", "Normal", "Slow"],
                                    state="readonly", width=7,
                                    font=(FONT_UI, 9))
        self._speed.set("Fast")
        self._speed.pack(side="left", padx=PAD_XS)
        self._run_btn = _button(top, "Hash", self._run)
        self._run_btn.pack(side="left")
        self._st = _ScrolledText(self, height=28, font_size=9)
        self._st.frame.pack(fill="both", expand=True, padx=PAD, pady=(0, PAD))
        for name, kw in [
            ("cyan", dict(foreground=ACCENT)),
            ("yellow", dict(foreground=WARNING)),
            ("green", dict(foreground=SUCCESS)),
            ("red", dict(foreground=DANGER)),
            ("dim", dict(foreground=FG_DIM)),
            ("bold", dict(font=(FONT_MONO, 9, "bold"))),
        ]:
            self._st.tag(name, **kw)
    @staticmethod
    def _rotr(x: int, n: int) -> int:
        """Rotate right a 32-bit unsigned integer by n bits."""
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
    def _run(self) -> None:
        if self._running:
            return
        text = self._input.get().strip()
        if not text:
            return
        self._st.clear()
        self._run_btn.config(state="disabled", text="Running…")
        self._running = True
        delay = {"Fast": 0.0, "Normal": 0.015, "Slow": 0.05}.get(
            self._speed.get(), 0.0)
        def w(line: str, tag: str | None = None) -> None:
            """Thread-safe write - schedules onto the Tk main thread."""
            self.after(0, lambda: self._st.write(line, tag))
        def worker() -> None:
            import time as _time

            msg = text.encode("utf-8")
            bit_len = len(msg) * 8
            rotr = HasherView._rotr
            w("  SHA-256 VISUALIZATION\n", "cyan")
            w("  " + "─" * 68 + "\n", "dim")
            w(f"  INPUT TEXT  : {repr(text)}\n")
            w(f"  UTF-8 BYTES : {' '.join(f'{b:02X}' for b in msg)}\n")
            w(f"  LENGTH      : {len(msg)} bytes = {bit_len} bits\n\n")
            w("  [ STEP 1 ] PRE-PROCESSING & PADDING\n", "bold")
            w("  Append 0x80, pad to 448 mod 512 bits, append 64-bit length.\n", "dim")
            padded = bytearray(msg) + b"\x80"
            while len(padded) % 64 != 56:
                padded += b"\x00"
            padded += bit_len.to_bytes(8, "big")
            blocks  = [bytes(padded[i:i+64]) for i in range(0, len(padded), 64)]
            w(f"  → {len(blocks)} block(s) of 512 bits\n\n")
            for bi, block in enumerate(blocks):
                w(f"  BLOCK {bi} (hex):\n", "yellow")
                for row in range(4):
                    seg = block[row * 16:(row + 1) * 16]
                    w("    " + " ".join(f"{b:02X}" for b in seg) + "\n", "dim")
            w("\n")
            w("  [ STEP 2 ] MESSAGE SCHEDULE W[0..63]  (Block 0)\n", "bold")
            w("  W[0..15] = block words · W[16..63] = sigma expansions\n", "dim")
            W = [int.from_bytes(blocks[0][i:i+4], "big") for i in range(0, 64, 4)]
            for i in range(16, 64):
                s0 = rotr(W[i-15], 7) ^ rotr(W[i-15], 18) ^ (W[i-15] >> 3)
                s1 = rotr(W[i-2],  17) ^ rotr(W[i-2],  19) ^ (W[i-2]  >> 10)
                W.append((W[i-16] + s0 + W[i-7] + s1) & 0xFFFFFFFF)
            for i in range(0, 64, 8):
                w("    " + "  ".join(
                    f"W[{i+j:02d}]={W[i+j]:08X}" for j in range(8)) + "\n", "dim")
            w("\n")
            w("  [ STEP 3 ] COMPRESSION - 64 ROUNDS\n", "bold")
            a, b, c, d, e, f, g, h = HasherView._H0
            w("  " + f"{'Rnd':>3}  " +
              "  ".join(f"{v:>10}" for v in "abcdefgh") + "\n", "yellow")
            w("  " + "─" * 96 + "\n", "dim")
            w("  " + f"{'0':>3}  {a:010X}  {b:010X}  {c:010X}  {d:010X}  "
              f"{e:010X}  {f:010X}  {g:010X}  {h:010X}\n", "dim")
            for i in range(64):
                S1 = rotr(e, 6)  ^ rotr(e, 11) ^ rotr(e, 25)
                ch = (e & f) ^ (~e & g) & 0xFFFFFFFF
                t1 = (h + S1 + ch + HasherView._K[i] + W[i]) & 0xFFFFFFFF
                S0 = rotr(a, 2)  ^ rotr(a, 13) ^ rotr(a, 22)
                maj = (a & b) ^ (a & c) ^ (b & c)
                t2 = (S0 + maj) & 0xFFFFFFFF
                h=g; g=f; f=e
                e=(d+t1) & 0xFFFFFFFF
                d=c; c=b; b=a
                a=(t1+t2) & 0xFFFFFFFF
                tag = "green" if i % 8 == 7 else None
                w("  " + f"{i+1:>3}  {a:010X}  {b:010X}  {c:010X}  {d:010X}  "
                  f"{e:010X}  {f:010X}  {g:010X}  {h:010X}\n", tag)
                if delay:
                    _time.sleep(delay)
            fh = [(HasherView._H0[i] + v) & 0xFFFFFFFF
                  for i, v in enumerate([a, b, c, d, e, f, g, h])]
            w("\n  [ STEP 4 ] ADD COMPRESSED CHUNK TO HASH VALUES\n", "bold")
            for lbl, val in zip(["H0","H1","H2","H3","H4","H5","H6","H7"], fh):
                w(f"    {lbl} = {val:08X}\n", "cyan")
            digest = "".join(f"{v:08X}" for v in fh).lower()
            expected = hashlib.sha256(msg).hexdigest()
            w("\n  [ FINAL ] SHA-256 DIGEST\n", "bold")
            w(f"  {digest}\n", "green")
            w(("  ✔  Verified correct against hashlib\n"
               if digest == expected
               else "  ✘  Mismatch with hashlib\n"),
              "dim" if digest == expected else "red")
            self.after(0, lambda: (
                setattr(self, "_running", False),
                self._run_btn.config(state="normal", text="Hash"),
            ))
        threading.Thread(target=worker, daemon=True).start()
class LogView(tk.Frame):
    """Displays the last 100 lines of the audit event log."""
    def __init__(self, master: tk.Widget) -> None:
        super().__init__(master, bg=BG)
        self._build()
    def _build(self) -> None:
        top = tk.Frame(self, bg=BG)
        top.pack(fill="x", padx=PAD, pady=(PAD, PAD_SM))
        _label(top, "Audit Log", size=16, bold=True).pack(side="left")
        _button(top, "Refresh", self._refresh, kind="ghost").pack(side="right")
        _separator(self).pack(fill="x", padx=PAD, pady=PAD_SM)
        self._st = _ScrolledText(self, height=32, font_size=10)
        self._st.frame.pack(fill="both", expand=True, padx=PAD, pady=(0, PAD))
        self._refresh()
    def _refresh(self) -> None:
        self._st.clear()
        lines = read_log(max_lines=100)
        if lines:
            for line in lines:
                self._st.write(f"  {line}\n")
        else:
            self._st.write("  No audit log entries yet.\n")
class MainFrame(tk.Frame):
    """
    Post-login shell: fixed sidebar + swappable content area + status bar.

    The sidebar holds navigation buttons and a Lock button.
    The status bar shows vault name, entry count, and a live countdown
    to auto-lock that updates every second via after() - no extra thread.
    """
    _NAV: list[tuple[str, str]] = [
        ("🔑  Credentials",    "vault"),
        ("➕  Add Entry",       "add"),
        ("🎲  Generator",       "generator"),
        ("🛡️  Security Audit",  "audit"),
        ("🔬  Hash Visualizer", "hasher"),
        ("📋  Audit Log",       "log"),
    ]
    def __init__(self, master: tk.Widget, session: Session,
                 on_lock) -> None:
        super().__init__(master, bg=BG)
        self._session  = session
        self._on_lock  = on_lock
        self._content: tk.Widget | None = None
        self._nav_btns: dict[str, tk.Button] = {}
        self._build()
        self._navigate("vault")
        self._tick()
    def _build(self) -> None:
        sidebar = tk.Frame(self, bg=BG_CARD, width=200)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        tk.Label(sidebar, text="🔐  PassWord", bg=BG_CARD, fg=ACCENT,
                 font=(FONT_UI, 14, "bold"), pady=PAD).pack(fill="x")
        _separator(sidebar).pack(fill="x")
        for label, key in self._NAV:
            btn = tk.Button(
                sidebar,
                text=f"  {label}",
                command=lambda k=key: self._navigate(k),
                bg=BG_CARD, fg=FG,
                activebackground=BG_HOVER, activeforeground=FG,
                relief="flat", bd=0,
                anchor="w", padx=PAD, pady=PAD_SM,
                cursor="hand2", font=(FONT_UI, 10),
            )
            btn.pack(fill="x")
            self._nav_btns[key] = btn
        tk.Frame(sidebar, bg=BG_CARD).pack(fill="both", expand=True)
        _separator(sidebar).pack(fill="x")
        tk.Button(
            sidebar, text="  🔒  Lock Vault", command=self._lock,
            bg=BG_CARD, fg=WARNING,
            activebackground=BG_HOVER, activeforeground=WARNING,
            relief="flat", bd=0, anchor="w",
            padx=PAD, pady=PAD_SM,
            cursor="hand2", font=(FONT_UI, 10),
        ).pack(fill="x")
        right = tk.Frame(self, bg=BG)
        right.pack(side="left", fill="both", expand=True)
        self._content_area = tk.Frame(right, bg=BG)
        self._content_area.pack(fill="both", expand=True)
        status = tk.Frame(right, bg=BG_CARD, height=24)
        status.pack(fill="x", side="bottom")
        status.pack_propagate(False)
        self._vault_lbl = tk.Label(status, text="", bg=BG_CARD, fg=FG_DIM,
                                      font=(FONT_UI, 8))
        self._entries_lbl = tk.Label(status, text="", bg=BG_CARD, fg=FG_DIM,
                                      font=(FONT_UI, 8))
        self._timer_lbl = tk.Label(status, text="", bg=BG_CARD, fg=FG_DIM,
                                      font=(FONT_UI, 8))
        self._vault_lbl.pack(  side="left",  padx=PAD_SM)
        self._timer_lbl.pack(  side="right", padx=PAD_SM)
        self._entries_lbl.pack(side="right", padx=PAD_SM)
    def _tick(self) -> None:
        """Refresh the status bar every second; lock if session has expired."""
        n = len(list_entries(self._session.payload))
        rem = max(0, SESSION_TIMEOUT_SEC - self._session.idle_seconds())
        mins, secs = divmod(rem, 60)
        self._vault_lbl.config(
            text=f"  Vault: {os.path.basename(self._session.vault_path)}")
        self._entries_lbl.config(text=f"Entries: {n}")
        self._timer_lbl.config(
            text=f"Auto-lock: {mins}:{secs:02d}  ",
            fg=WARNING if rem < 60 else FG_DIM)
        if rem == 0:
            self._lock()
            return
        self.after(1000, self._tick)
    def _highlight_nav(self, active_key: str) -> None:
        for key, btn in self._nav_btns.items():
            btn.config(bg=BG_SELECTED if key == active_key else BG_CARD,
                       fg=ACCENT if key == active_key else FG)
    def _clear_content(self) -> None:
        if self._content:
            self._content.destroy()
            self._content = None
    def _navigate(self, key: str) -> None:
        self._session.touch()
        self._highlight_nav(key)
        self._clear_content()
        views = {
            "vault":     lambda: VaultView(
                             self._content_area, self._session,
                             on_edit=self._show_edit,
                             on_delete=self._delete_entry),
            "add":       lambda: AddEditView(
                             self._content_area, self._session,
                             on_save=lambda: self._navigate("vault"),
                             on_cancel=lambda: self._navigate("vault")),
            "generator": lambda: GeneratorView(self._content_area),
            "audit":     lambda: AuditView(self._content_area, self._session),
            "hasher":    lambda: HasherView(self._content_area),
            "log":       lambda: LogView(self._content_area),
        }
        self._content = views[key]()
        self._content.pack(fill="both", expand=True)
    def _show_edit(self, entry: dict) -> None:
        self._clear_content()
        self._highlight_nav("")
        self._content = AddEditView(
            self._content_area, self._session,
            on_save=lambda: self._navigate("vault"),
            on_cancel=lambda: self._navigate("vault"),
            entry=entry,
        )
        self._content.pack(fill="both", expand=True)
    def _delete_entry(self, entry: dict) -> None:
        if not msgbox.askyesno(
            "Confirm Delete",
            f"Permanently delete the entry for '{entry['site']}'?\n\n"
            "This cannot be undone.",
        ):
            return
        delete_entry(self._session.payload, entry["id"])
        self._session.save()
        log_event("ENTRY_DELETED", str(entry["id"]))
        self._navigate("vault")
    def _lock(self) -> None:
        self._session.lock()
        self._on_lock()
class App(tk.Tk):
    """
    Root window.

    Manages two mutually exclusive top-level states:
      · LoginFrame - shown before authentication and after lock
      · MainFrame  - shown after successful authentication

    The window-close handler calls ``session.close()`` to zero the key
    before the process exits.
    """
    def __init__(self) -> None:
        super().__init__()
        self.title("PassWord - AES-256 Password Manager")
        self.geometry("1000x680")
        self.minsize(800, 560)
        self.configure(bg=BG)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("TCombobox",
                         fieldbackground=BG_INPUT, background=BG_CARD,
                         foreground=FG, selectbackground=ACCENT_DIM)
        self._frame: tk.Frame | None = None
        self._show_login()
    def _swap(self, new_frame: tk.Frame) -> None:
        """Destroy the current top-level frame and display a new one."""
        if self._frame:
            self._frame.destroy()
        self._frame = new_frame
        self._frame.pack(fill="both", expand=True)
    def _show_login(self) -> None:
        self._swap(LoginFrame(self, on_success=self._on_login))
    def _on_login(self, session: Session) -> None:
        self._swap(MainFrame(self, session, on_lock=self._show_login))
    def _on_close(self) -> None:
        """Zero the session key before destroying the window."""
        if isinstance(self._frame, MainFrame):
            self._frame._session.close()
        self.destroy()
def main() -> None:
    App().mainloop()
if __name__ == "__main__":
    main()