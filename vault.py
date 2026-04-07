# vault.py >>> binary .vault format, HMAC verification, encrypted audit logger
import os
import json
from constants import (
    VAULT_MAGIC, VAULT_VERSION,
    SALT_SIZE, IV_SIZE, HMAC_SIZE, AES_BLOCK_SIZE,
    LOG_FILE,
    VaultCorruptedError, VaultTamperedError, VaultNotFoundError,
    secure_random_bytes, pack_uint32, unpack_uint32,
    current_timestamp, format_timestamp,
    COLOR_DIM, COLOR_RESET, COLOR_CYAN
)
from crypto import aes_encrypt_cbc, aes_decrypt_cbc, compute_hmac, verify_hmac
def save_vault(path: str, payload: dict, key: bytes) -> None:
    """
    Encrypt and write the vault payload to disk.

    Procedure:
    1. Serialize payload dict to JSON bytes
    2. Generate a fresh random IV (NEVER reuse!)
    3. Encrypt with AES-256-CBC
    4. Assemble header + ciphertext
    5. Compute HMAC-SHA256 over the entire header + ciphertext
    6. Write header + ciphertext + HMAC to file atomically

    Args:
        path:    File path for the vault (e.g. "my.vault").
        payload: Python dict — the decrypted vault contents.
        key:     32-byte AES-256 key derived from master password.
    """
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    iv         = secure_random_bytes(IV_SIZE)
    ciphertext = aes_encrypt_cbc(plaintext, key, iv)
    data_len   = pack_uint32(len(ciphertext))
    salt = _read_salt(path)
    header     = VAULT_MAGIC + bytes([VAULT_VERSION]) + salt + iv + data_len
    auth_data  = header + ciphertext
    mac = compute_hmac(key, auth_data)
    tmp_path = path + ".tmp"
    with open(tmp_path, "wb") as f:
        f.write(auth_data)
        f.write(mac)
    os.replace(tmp_path, path)
def load_vault(path: str, key: bytes) -> dict:
    """
    Read, verify, and decrypt the vault file.

    Procedure:
    1. Read raw bytes
    2. Validate magic bytes and version
    3. Parse header fields
    4. Verify HMAC BEFORE any decryption (Encrypt-then-MAC pattern)
    5. Decrypt ciphertext with AES-256-CBC
    6. Deserialize JSON

    Args:
        path: File path of the vault.
        key:  32-byte AES-256 key derived from master password.

    Returns:
        Decrypted payload as a Python dict.

    Raises:
        VaultNotFoundError:   If file does not exist.
        VaultCorruptedError:  If magic bytes, version, or structure is invalid.
        VaultTamperedError:   If HMAC verification fails.
    """
    if not os.path.exists(path):
        raise VaultNotFoundError(f"Vault not found: {path}")
    with open(path, "rb") as f:
        raw = f.read()
    if len(raw) < 57 + AES_BLOCK_SIZE + HMAC_SIZE:
        raise VaultCorruptedError("Vault file is too small to be valid.")
    if raw[:4] != VAULT_MAGIC:
        raise VaultCorruptedError(f"Invalid magic bytes: {raw[:4]!r} (expected {VAULT_MAGIC!r})")
    version = raw[4]
    if version != VAULT_VERSION:
        raise VaultCorruptedError(f"Unsupported vault version: {version}")
    salt       = raw[5:5+SALT_SIZE]                         # 32 bytes
    iv         = raw[5+SALT_SIZE:5+SALT_SIZE+IV_SIZE]       # 16 bytes
    data_len   = unpack_uint32(raw[5+SALT_SIZE+IV_SIZE:5+SALT_SIZE+IV_SIZE+4])  # 4 bytes
    ct_start   = 5 + SALT_SIZE + IV_SIZE + 4
    ct_end     = ct_start + data_len
    auth_data  = raw[:ct_end]
    stored_mac = raw[ct_end:ct_end+HMAC_SIZE]
    if len(raw) != ct_end + HMAC_SIZE:
        raise VaultCorruptedError("Vault file has unexpected trailing bytes.")
    if not verify_hmac(key, auth_data, stored_mac):
        raise VaultTamperedError(
            "HMAC verification failed. "
            "The vault may have been tampered with, or the master password is wrong."
        )
    ciphertext = raw[ct_start:ct_end]
    plaintext  = aes_decrypt_cbc(ciphertext, key, iv)
    return json.loads(plaintext.decode("utf-8"))
def init_vault(path: str, key: bytes, salt: bytes = None) -> dict:
    """
    Create a brand-new empty vault at the given path.
    Generates (or accepts) a salt, writes an empty encrypted payload.

    Args:
        path: File path for the new vault.
        key:  32-byte AES-256 key derived from the master password + salt.
        salt: Optional 32-byte salt. Generated fresh if not provided.

    Returns:
        The empty payload dict.
    """
    payload = {
        "entries":  [],
        "created":  current_timestamp(),
        "modified": current_timestamp(),
    }
    if salt is None:
        salt = secure_random_bytes(SALT_SIZE)
    _write_salt_stub(path, salt)
    save_vault(path, payload, key)
    return payload
def vault_exists(path: str) -> bool:
    """Return True if a vault file exists at the given path."""
    return os.path.exists(path)
def _write_salt_stub(path: str, salt: bytes) -> None:
    """
    Write a minimal file containing just the salt so it can be read back.
    This is overwritten immediately by save_vault with the real content.
    The salt must persist across saves — changing it would invalidate the key.
    """
    stub = VAULT_MAGIC + bytes([VAULT_VERSION]) + salt
    with open(path, "wb") as f:
        f.write(stub)
def _read_salt(path: str) -> bytes:
    """
    Read the 32-byte salt from an existing vault file.
    Returns a fresh random salt if the file does not exist yet.
    """
    if not os.path.exists(path):
        return secure_random_bytes(SALT_SIZE)
    with open(path, "rb") as f:
        raw = f.read(5 + SALT_SIZE)
    if len(raw) < 5 + SALT_SIZE:
        return secure_random_bytes(SALT_SIZE)
    return raw[5:5+SALT_SIZE]
def get_salt(path: str) -> bytes:
    """
    Public interface: read the salt from the vault file.
    Called by auth.py to derive the key before opening the vault.
    """
    return _read_salt(path)
def list_entries(payload: dict) -> list[dict]:
    """Return the list of all credential entries in the vault."""
    return payload.get("entries", [])
def find_entries(payload: dict, query: str) -> list[dict]:
    """
    Search entries by site, username, or notes (case-insensitive substring match).
    Returns all matching entries.
    """
    q = query.lower()
    return [
        e for e in payload.get("entries", [])
        if q in e.get("site", "").lower()
        or q in e.get("username", "").lower()
        or q in e.get("notes", "").lower()
    ]
def add_entry(payload: dict, site: str, username: str,
              password: str, notes: str = "") -> dict:
    """
    Add a new credential entry to the vault payload.
    Does not write to disk — caller must call save_vault afterwards.

    Returns the newly created entry dict.
    """
    entry = {
        "id":       _next_id(payload),
        "site":     site.strip(),
        "username": username.strip(),
        "password": password,
        "notes":    notes.strip(),
        "created":  current_timestamp(),
        "modified": current_timestamp(),
    }
    payload["entries"].append(entry)
    payload["modified"] = current_timestamp()
    return entry
def update_entry(payload: dict, entry_id: int,
                 site: str = None, username: str = None,
                 password: str = None, notes: str = None) -> bool:
    """
    Update fields of an existing entry by its numeric ID.
    Only updates fields that are not None.
    Returns True if the entry was found and updated.
    """
    for entry in payload["entries"]:
        if entry["id"] == entry_id:
            if site is not None: entry["site"]     = site.strip()
            if username is not None: entry["username"] = username.strip()
            if password is not None: entry["password"] = password
            if notes is not None: entry["notes"]    = notes.strip()
            entry["modified"] = current_timestamp()
            payload["modified"] = current_timestamp()
            return True
    return False
def delete_entry(payload: dict, entry_id: int) -> bool:
    """
    Remove an entry from the vault by its numeric ID.
    Returns True if the entry was found and deleted.
    """
    before = len(payload["entries"])
    payload["entries"] = [e for e in payload["entries"] if e["id"] != entry_id]
    if len(payload["entries"]) < before:
        payload["modified"] = current_timestamp()
        return True
    return False
def _next_id(payload: dict) -> int:
    """Generate the next sequential entry ID (simple auto-increment)."""
    entries = payload.get("entries", [])
    if not entries:
        return 1
    return max(e["id"] for e in entries) + 1
def get_duplicate_passwords(payload: dict) -> list[list[dict]]:
    """
    Find groups of entries that share the same password.
    Returns a list of groups, where each group is a list of entries
    with the same password value. Groups with only one entry are excluded.
    """
    from collections import defaultdict
    groups: dict = defaultdict(list)
    for entry in payload.get("entries", []):
        groups[entry["password"]].append(entry)
    return [group for group in groups.values() if len(group) > 1]
def get_old_passwords(payload: dict, max_age_days: int) -> list[dict]:
    """
    Return entries whose password has not been changed in more than max_age_days.
    Uses the entry's 'modified' timestamp.
    """
    cutoff = current_timestamp() - (max_age_days * 86400)
    return [e for e in payload.get("entries", []) if e.get("modified", 0) < cutoff]
def log_event(event: str, detail: str = "") -> None:
    """
    Append a timestamped security event to the audit log.

    Log format per line:
        [YYYY-MM-DD HH:MM UTC] EVENT | detail

    Events never contain sensitive data (passwords, keys).
    The log file itself is plaintext — in a production system,
    it would be encrypted with a separate log key.
    """
    ts = format_timestamp(current_timestamp())
    line = f"[{ts}] {event}"
    if detail:
        line += f" | {detail}"
    line += "\n"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass
def read_log(max_lines: int = 30) -> list[str]:
    """
    Read the last max_lines entries from the audit log.
    Returns an empty list if the log file does not exist.
    """
    if not os.path.exists(LOG_FILE):
        return []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
        return [line.rstrip() for line in lines[-max_lines:]]
    except OSError:
        return []
def print_log() -> None:
    """Pretty-print the audit log to the terminal."""
    lines = read_log()
    if not lines:
        print(f"  {COLOR_DIM}No audit log entries found.{COLOR_RESET}")
        return
    print(f"\n  {COLOR_CYAN}AUDIT LOG (last {len(lines)} entries):{COLOR_RESET}\n")
    for line in lines:
        print(f"  {COLOR_DIM}{line}{COLOR_RESET}")
