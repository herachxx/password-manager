# main.py >> entry point, authentication, session management, CLI menus
import sys
import os
import getpass
from constants import (
    DEFAULT_VAULT_NAME, MIN_MASTER_LENGTH,
    MAX_LOGIN_ATTEMPTS, LOCKOUT_FILE, LOCKOUT_DURATION,
    SESSION_TIMEOUT_SEC, PBKDF2_ITERATIONS,
    COLOR_RESET, COLOR_CYAN, COLOR_BOLD, COLOR_DIM,
    COLOR_RED, TERM_WIDTH,
    AuthenticationError, LockoutError, SessionExpiredError,
    VaultCorruptedError, VaultTamperedError,
    PasswordPolicyError,
    secure_random_bytes, zero_bytes, current_timestamp, format_timestamp,
    banner, success, error, warn, info, divider, prompt, confirm,
    strength_label
)
from crypto import derive_key, visualize_sha256
from vault import (
    vault_exists, init_vault, load_vault, save_vault, get_salt,
    list_entries, find_entries, add_entry, update_entry, delete_entry,
    print_log, log_event
)
from tools import (
    interactive_generator, audit_vault, run_bruteforce_simulator,
    password_entropy, print_password_stats
)
# LOCKOUT MANAGEMENT
def _read_lockout() -> tuple[int, int]:
    """
    Read the lockout state from the hidden lockout file.
    Returns (attempt_count, last_attempt_timestamp).
    Returns (0, 0) if no lockout file exists.
    """
    if not os.path.exists(LOCKOUT_FILE):
        return 0, 0
    try:
        with open(LOCKOUT_FILE, "r") as f:
            parts = f.read().strip().split()
        return int(parts[0]), int(parts[1])
    except (ValueError, IndexError, OSError):
        return 0, 0
def _write_lockout(attempts: int, timestamp: int) -> None:
    """Persist the current attempt count and timestamp."""
    try:
        with open(LOCKOUT_FILE, "w") as f:
            f.write(f"{attempts} {timestamp}\n")
    except OSError:
        pass
def _clear_lockout() -> None:
    """Remove the lockout file after a successful login."""
    try:
        os.remove(LOCKOUT_FILE)
    except OSError:
        pass
def _check_lockout() -> None:
    """
    Raise LockoutError if the user is currently locked out.
    A lockout expires after LOCKOUT_DURATION seconds.
    After expiry, the attempt counter resets automatically.
    """
    attempts, last_attempt = _read_lockout()
    if attempts < MAX_LOGIN_ATTEMPTS:
        return
    elapsed = current_timestamp() - last_attempt
    remaining = LOCKOUT_DURATION - elapsed
    if remaining > 0:
        raise LockoutError(int(remaining))
    else:
        _clear_lockout()
def _record_failed_attempt() -> None:
    """Increment the failed attempt counter."""
    attempts, _ = _read_lockout()
    _write_lockout(attempts + 1, current_timestamp())
def _validate_master_password(password: str) -> None:
    """
    Enforce minimum master password policy.
    Raises PasswordPolicyError if requirements are not met.
    """
    if len(password) < MIN_MASTER_LENGTH:
        raise PasswordPolicyError(
            f"Master password must be at least {MIN_MASTER_LENGTH} characters."
        )
    has_upper  = any(c.isupper()  for c in password)
    has_digit  = any(c.isdigit()  for c in password)
    if not has_upper or not has_digit:
        raise PasswordPolicyError(
            "Master password must contain at least one uppercase letter and one digit."
        )
def create_vault_flow(vault_path: str) -> tuple[bytearray, dict]:
    """
    Guide the user through creating a new vault.
    Returns (key_buffer, payload) — key as a zeroed-on-exit bytearray.
    """
    banner("CREATE NEW VAULT")
    print(f"""
  {COLOR_DIM}No vault found at: {vault_path}
  Let's create one. Choose a strong master password — it is the ONLY
  thing protecting all your credentials. It cannot be recovered if lost.
  
  Requirements: {MIN_MASTER_LENGTH}+ characters, 1 uppercase letter, 1 digit.{COLOR_RESET}
""")
    while True:
        pw1 = getpass.getpass("  Master password : ")
        try:
            _validate_master_password(pw1)
        except PasswordPolicyError as e:
            error(str(e))
            continue
        bits = password_entropy(pw1)
        print_password_stats(pw1)
        if bits < 50:
            warn("That password is weak. A stronger master password is strongly recommended.")
            if not confirm("  Use it anyway?"):
                continue
        pw2 = getpass.getpass("  Confirm password: ")
        if pw1 != pw2:
            error("Passwords do not match. Try again.")
            continue
        break
    print(f"\n  {COLOR_DIM}Deriving key with PBKDF2-SHA256 ({PBKDF2_ITERATIONS:,} iterations)...")
    print(f"  This intentional slowness protects against brute-force attacks.{COLOR_RESET}\n")
    salt    = secure_random_bytes(32)
    key_buf = bytearray(derive_key(pw1, salt))
    pw1 = None
    pw2 = None
    payload = init_vault(vault_path, bytes(key_buf), salt=salt)
    log_event("VAULT_CREATED", vault_path)
    success("Vault created successfully.")
    return key_buf, payload
def login_flow(vault_path: str) -> tuple[bytearray, dict]:
    """
    Authenticate the user against an existing vault.
    Returns (key_buffer, payload) on success.
    Raises AuthenticationError, LockoutError, VaultTamperedError.
    """
    banner("VAULT LOGIN")
    _check_lockout()
    attempts, _ = _read_lockout()
    remaining_attempts = MAX_LOGIN_ATTEMPTS - attempts
    if attempts > 0:
        warn(f"Previous failed attempts: {attempts}. {remaining_attempts} attempt(s) remaining.")
    pw = getpass.getpass("  Master password: ")
    print(f"\n  {COLOR_DIM}Deriving key ({PBKDF2_ITERATIONS:,} iterations)...{COLOR_RESET}")
    salt    = get_salt(vault_path)
    key_buf = bytearray(derive_key(pw, salt))
    pw      = None
    try:
        payload = load_vault(vault_path, bytes(key_buf))
    except VaultTamperedError:
        _record_failed_attempt()
        log_event("LOGIN_FAILED", "HMAC verification failed")
        raise
    except Exception:
        _record_failed_attempt()
        log_event("LOGIN_FAILED", "Key derivation mismatch")
        # Raise generic AuthenticationError — never leak which check failed
        raise AuthenticationError("Incorrect master password.")
    _clear_lockout()
    log_event("LOGIN_SUCCESS")
    success("Vault unlocked.")
    return key_buf, payload
class Session:
    """
    Holds the active session state.
    Owns the key buffer — responsible for zeroing it on exit.
    Tracks last activity time for auto-lock enforcement.
    """
    def __init__(self, key_buf: bytearray, payload: dict, vault_path: str):
        self.key_buf      = key_buf
        self.payload      = payload
        self.vault_path   = vault_path
        self.last_activity = current_timestamp()
        self.locked       = False
    def touch(self) -> None:
        """Update last activity timestamp — call before any user interaction."""
        self.last_activity = current_timestamp()
    def check_timeout(self) -> None:
        """Raise SessionExpiredError if session has been idle too long."""
        idle = current_timestamp() - self.last_activity
        if idle >= SESSION_TIMEOUT_SEC:
            self.lock()
            raise SessionExpiredError(
                f"Session timed out after {SESSION_TIMEOUT_SEC // 60} minutes of inactivity."
            )
    def save(self) -> None:
        """Encrypt and persist the current payload to disk."""
        save_vault(self.vault_path, self.payload, bytes(self.key_buf))
        log_event("VAULT_SAVED")
    def lock(self) -> None:
        """Zero the key from memory and mark session as locked."""
        zero_bytes(self.key_buf)
        self.locked = True
        log_event("SESSION_LOCKED")
    def close(self) -> None:
        """Gracefully close the session and wipe the key."""
        self.lock()
        log_event("SESSION_CLOSED")
def _print_entry(entry: dict, show_password: bool = False) -> None:
    """Pretty-print a single credential entry."""
    from constants import format_timestamp
    pw_display = entry["password"] if show_password else "●" * min(len(entry["password"]), 16)
    bits       = password_entropy(entry["password"])
    label, color = strength_label(bits)
    print(f"\n  {COLOR_BOLD}[{entry['id']}] {entry['site']}{COLOR_RESET}")
    print(f"  Username : {entry['username']}")
    print(f"  Password : {pw_display}  ({color}{label}{COLOR_RESET}, {bits:.0f} bits)")
    if entry.get("notes"):
        print(f"  Notes    : {entry['notes']}")
    print(f"  {COLOR_DIM}Modified : {format_timestamp(entry['modified'])}{COLOR_RESET}")
def menu_list(session: Session) -> None:
    """List all entries in the vault."""
    entries = list_entries(session.payload)
    if not entries:
        info("No entries in vault. Add one first.")
        return
    banner(f"ALL ENTRIES  ({len(entries)} total)")
    for entry in entries:
        _print_entry(entry, show_password=False)
        divider()
def menu_search(session: Session) -> None:
    """Search entries by site, username, or notes."""
    banner("SEARCH")
    query   = prompt("Search query: ")
    results = find_entries(session.payload, query)
    if not results:
        info(f"No entries matching '{query}'.")
        return
    print(f"\n  Found {len(results)} result(s) for '{query}':\n")
    for entry in results:
        reveal = confirm(f"  Show password for [{entry['id']}] {entry['site']}?")
        _print_entry(entry, show_password=reveal)
        divider()
def menu_add(session: Session) -> None:
    """Add a new credential entry."""
    banner("ADD ENTRY")
    site     = prompt("Site / Service name  : ")
    username = prompt("Username / Email     : ")
    if not site or not username:
        error("Site and username are required.")
        return
    if confirm("Generate a strong password automatically?"):
        password = interactive_generator()
        if not password:
            return
    else:
        password = getpass.getpass("  Password: ")
        if not password:
            error("Password cannot be empty.")
            return
        print_password_stats(password)
    notes = prompt("Notes (optional)     : ")
    entry = add_entry(session.payload, site, username, password, notes)
    session.save()
    log_event("ENTRY_ADDED", site)
    success(f"Entry [{entry['id']}] saved for {site}.")
def menu_edit(session: Session) -> None:
    """Edit an existing entry by ID."""
    banner("EDIT ENTRY")
    menu_list(session)
    try:
        entry_id = int(prompt("Entry ID to edit: "))
    except ValueError:
        error("Invalid ID.")
        return
    matches = [e for e in list_entries(session.payload) if e["id"] == entry_id]
    if not matches:
        error(f"No entry with ID {entry_id}.")
        return
    entry = matches[0]
    _print_entry(entry, show_password=False)
    print(f"\n  {COLOR_DIM}Leave any field blank to keep the current value.{COLOR_RESET}\n")
    site = prompt(f"New site [{entry['site']}]         : ") or None
    username = prompt(f"New username [{entry['username']}]: ") or None
    new_pw = None
    if confirm("Change password?"):
        if confirm("Generate a strong password?"):
            new_pw = interactive_generator()
        else:
            new_pw = getpass.getpass("  New password: ") or None
            if new_pw:
                print_password_stats(new_pw)
    notes = prompt(f"New notes [{entry.get('notes','')[:20]}]: ") or None
    if update_entry(session.payload, entry_id, site, username, new_pw, notes):
        session.save()
        log_event("ENTRY_UPDATED", str(entry_id))
        success(f"Entry [{entry_id}] updated.")
    else:
        error("Update failed.")
def menu_delete(session: Session) -> None:
    """Delete an entry by ID with confirmation."""
    banner("DELETE ENTRY")
    menu_list(session)
    try:
        entry_id = int(prompt("Entry ID to delete: "))
    except ValueError:
        error("Invalid ID.")
        return
    matches = [e for e in list_entries(session.payload) if e["id"] == entry_id]
    if not matches:
        error(f"No entry with ID {entry_id}.")
        return
    _print_entry(matches[0], show_password=False)
    if not confirm(f"\n  {COLOR_RED}Permanently delete this entry?{COLOR_RESET}"):
        info("Deletion cancelled.")
        return
    if delete_entry(session.payload, entry_id):
        session.save()
        log_event("ENTRY_DELETED", str(entry_id))
        success(f"Entry [{entry_id}] deleted.")
    else:
        error("Deletion failed.")
def _print_main_menu(vault_path: str, entry_count: int) -> None:
    """Render the main menu."""
    idle_mins = SESSION_TIMEOUT_SEC // 60
    print(f"\n{COLOR_CYAN}{'─' * TERM_WIDTH}{COLOR_RESET}")
    print(f"{COLOR_BOLD}  VAULT: {vault_path}  |  ENTRIES: {entry_count}  |  AUTO-LOCK: {idle_mins}min{COLOR_RESET}")
    print(f"{COLOR_CYAN}{'─' * TERM_WIDTH}{COLOR_RESET}")
    print(f"""
  {COLOR_BOLD}CREDENTIALS{COLOR_RESET}
    [1]  List all entries
    [2]  Search entries
    [3]  Add new entry
    [4]  Edit entry
    [5]  Delete entry

  {COLOR_BOLD}TOOLS{COLOR_RESET}
    [6]  Password generator
    [7]  Security audit
    [8]  Bruteforce simulator
    [9]  SHA-256 hash visualizer

  {COLOR_BOLD}SYSTEM{COLOR_RESET}
    [A]  View audit log
    [L]  Lock vault
    [Q]  Quit
""")
def run_main_menu(session: Session) -> None:
    """
    Main interactive loop. Routes user input to the appropriate handler.
    Enforces session timeout on every iteration.
    """
    while True:
        try:
            session.check_timeout()
        except SessionExpiredError as e:
            warn(str(e))
            return
        entry_count = len(list_entries(session.payload))
        _print_main_menu(session.vault_path, entry_count)
        choice = prompt("Choice: ").upper()
        session.touch()
        try:
            if   choice == "1": menu_list(session)
            elif choice == "2": menu_search(session)
            elif choice == "3": menu_add(session)
            elif choice == "4": menu_edit(session)
            elif choice == "5": menu_delete(session)
            elif choice == "6": interactive_generator()
            elif choice == "7": audit_vault(session.payload)
            elif choice == "8": run_bruteforce_simulator()
            elif choice == "9": _menu_hash_visualizer()
            elif choice == "A": print_log()
            elif choice == "L":
                session.lock()
                warn("Vault locked. Restart to unlock.")
                return
            elif choice == "Q":
                if confirm("  Save and quit?"):
                    session.close()
                    print(f"\n  {COLOR_DIM}Key wiped from memory. Goodbye.{COLOR_RESET}\n")
                    sys.exit(0)
            else:
                warn("Unknown option. Enter a number or letter from the menu.")
        except (VaultCorruptedError, VaultTamperedError) as e:
            error(str(e))
            session.close()
            sys.exit(1)
        except KeyboardInterrupt:
            print()
            warn("Use [Q] to quit safely and wipe the key from memory.")
def _menu_hash_visualizer() -> None:
    """SHA-256 visualizer sub-menu."""
    banner("SHA-256 HASH VISUALIZER")
    print(f"""
  {COLOR_DIM}Watch SHA-256 process your input byte by byte:
  - Pre-processing & padding
  - Message schedule construction (W[0..63])
  - All 64 compression rounds (working variables a..h)
  - Final digest assembly{COLOR_RESET}
""")
    text = prompt("Enter text to hash: ")
    if not text:
        warn("No text entered.")
        return
    try:
        speed_choice = prompt("Animation speed — (1) Fast  (2) Normal  (3) Slow [2]: ")
        delays = {"1": 0.01, "2": 0.03, "3": 0.08}
        delay = delays.get(speed_choice, 0.03)
    except Exception:
        delay = 0.03
    visualize_sha256(text, delay=delay)
def main() -> None:
    """
    Application entry point.

    Flow:
    1. Print splash screen
    2. Determine vault path (CLI arg or default)
    3. Create or unlock vault
    4. Run main menu loop
    5. Handle re-login after session timeout
    """
    print(f"""
{COLOR_CYAN}{COLOR_BOLD}
  ██████╗  █████╗ ███████╗███████╗██╗    ██╗ ██████╗ ██████╗ ██████╗
  ██╔══██╗██╔══██╗██╔════╝██╔════╝██║    ██║██╔═══██╗██╔══██╗██╔══██╗
  ██████╔╝███████║███████╗███████╗██║ █╗ ██║██║   ██║██████╔╝██║  ██║
  ██╔═══╝ ██╔══██║╚════██║╚════██║██║███╗██║██║   ██║██╔══██╗██║  ██║
  ██║     ██║  ██║███████║███████║╚███╔███╔╝╚██████╔╝██║  ██║██████╔╝
  ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝
{COLOR_RESET}
  {COLOR_DIM}AES-256 · PBKDF2-SHA256 ({PBKDF2_ITERATIONS:,} iters) · HMAC-SHA256 · Zero external deps{COLOR_RESET}
""")
    vault_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_VAULT_NAME
    while True:
        try:
            if not vault_exists(vault_path):
                key_buf, payload = create_vault_flow(vault_path)
            else:
                key_buf, payload = login_flow(vault_path)
        except LockoutError as e:
            error(f"Too many failed attempts. Try again in {e.seconds_remaining} seconds.")
            sys.exit(1)
        except AuthenticationError as e:
            error(str(e))
            attempts, _ = _read_lockout()
            remaining   = MAX_LOGIN_ATTEMPTS - attempts
            if remaining > 0:
                warn(f"{remaining} attempt(s) remaining before lockout.")
                continue
            else:
                error(f"Locked out for {LOCKOUT_DURATION} seconds.")
                sys.exit(1)
        except (VaultCorruptedError, VaultTamperedError) as e:
            error(str(e))
            sys.exit(1)
        except KeyboardInterrupt:
            print(f"\n  {COLOR_DIM}Interrupted. No data written.{COLOR_RESET}\n")
            sys.exit(0)
        session = Session(key_buf, payload, vault_path)
        run_main_menu(session)
        if session.locked:
            info("Enter master password to unlock.")
        else:
            break
if __name__ == "__main__":
    main()
