# constants.py >>> single source of truth for all constants, exceptions, utils
import os
import time
import struct
import hmac as hmac_module
AES_KEY_SIZE        = 32          # 256-bit AES key
AES_BLOCK_SIZE      = 16          # AES block is always 128 bits
PBKDF2_ITERATIONS   = 600_000     # NIST-recommended minimum for PBKDF2-SHA256
PBKDF2_HASH         = "sha256"    # Hash algorithm for PBKDF2
SALT_SIZE           = 32          # 256-bit random salt
IV_SIZE             = 16          # 128-bit AES initialization vector
HMAC_SIZE           = 32          # 256-bit HMAC-SHA256 digest
VAULT_MAGIC         = b"PVLT"     # 4-byte magic number to identify vault files
VAULT_VERSION       = 1           # File format version byte
VAULT_EXTENSION     = ".vault"    # Vault file extension
DEFAULT_VAULT_NAME  = "my.vault"  # Default vault filename
VAULT_HEADER_SIZE   = 4 + 1 + SALT_SIZE + IV_SIZE + 4   # 57 bytes
VAULT_FOOTER_SIZE   = HMAC_SIZE                          # 32 bytes
SESSION_TIMEOUT_SEC = 300         # Auto-lock after 5 minutes of inactivity
MAX_LOGIN_ATTEMPTS  = 3           # Lockout after this many failed attempts
LOCKOUT_FILE        = ".lockout"  # Hidden file tracking failed attempts
LOCKOUT_DURATION    = 30          # Seconds to wait after MAX_LOGIN_ATTEMPTS
MIN_MASTER_LENGTH   = 12          # Minimum master password length
MIN_GEN_LENGTH      = 8           # Minimum generated password length
MAX_GEN_LENGTH      = 128         # Maximum generated password length
DEFAULT_GEN_LENGTH  = 20          # Default generated password length
PASSWORD_AGE_WARN   = 90          # Warn if password older than N days
LOG_FILE            = ".audit.log"  # Hidden encrypted audit log
LOG_SEPARATOR       = b"|"          # Field separator in log entries
TERM_WIDTH          = 72          # Consistent terminal width for all output
COLOR_RESET         = "\033[0m"
COLOR_RED           = "\033[91m"
COLOR_GREEN         = "\033[92m"
COLOR_YELLOW        = "\033[93m"
COLOR_CYAN          = "\033[96m"
COLOR_BOLD          = "\033[1m"
COLOR_DIM           = "\033[2m"
class VaultError(Exception):
    """Base exception for all vault-related errors."""
    pass
class VaultCorruptedError(VaultError):
    """Raised when vault file structure is invalid or magic bytes mismatch."""
    pass
class VaultTamperedError(VaultError):
    """Raised when HMAC verification fails — vault may have been modified."""
    pass
class VaultNotFoundError(VaultError):
    """Raised when the vault file does not exist on disk."""
    pass
class AuthenticationError(Exception):
    """Raised when master password is incorrect."""
    pass
class LockoutError(Exception):
    """Raised when the user is locked out after too many failed attempts."""
    def __init__(self, seconds_remaining: int):
        self.seconds_remaining = seconds_remaining
        super().__init__(f"Locked out for {seconds_remaining} more seconds.")
class SessionExpiredError(Exception):
    """Raised when the session has timed out due to inactivity."""
    pass
class PasswordPolicyError(Exception):
    """Raised when a password does not meet minimum requirements."""
    pass
def secure_random_bytes(n: int) -> bytes:
    """
    Return N cryptographically secure random bytes.
    Wraps os.urandom — the only correct source of randomness for crypto.
    """
    return os.urandom(n)
def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings in constant time.
    Prevents timing attacks where an attacker measures response time
    to learn how many bytes of a secret they guessed correctly.
    """
    return hmac_module.compare_digest(a, b)
def zero_bytes(buf: bytearray) -> None:
    """
    Overwrite a bytearray with zeros in place.
    Used to wipe sensitive key material from memory after use.
    Python's GC does not guarantee when memory is reclaimed,
    so we zero it explicitly before releasing the reference.
    """
    for i in range(len(buf)):
        buf[i] = 0
def pack_uint32(value: int) -> bytes:
    """Pack an unsigned 32-bit integer as 4 big-endian bytes."""
    return struct.pack(">I", value)
def unpack_uint32(data: bytes) -> int:
    """Unpack an unsigned 32-bit integer from 4 big-endian bytes."""
    return struct.unpack(">I", data)[0]
def current_timestamp() -> int:
    """Return the current UTC time as a Unix timestamp (integer seconds)."""
    return int(time.time())
def format_timestamp(ts: int) -> str:
    """Convert a Unix timestamp to a human-readable UTC string."""
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts))
def entropy_bits(length: int, charset_size: int) -> float:
    """
    Calculate the Shannon entropy of a random password.

    Formula: entropy = length * log2(charset_size)
    Example: 20 chars from 94-char printable ASCII = 20 * 6.55 ≈ 131 bits.
    NIST considers 80+ bits strong, 128+ bits very strong.
    """
    import math
    if charset_size <= 0 or length <= 0:
        return 0.0
    return length * math.log2(charset_size)
def strength_label(bits: float) -> tuple[str, str]:
    """
    Convert entropy bits to a human-readable strength label and color.
    Returns (label, color_code).
    """
    if bits < 28:
        return "Very Weak", COLOR_RED
    elif bits < 36:
        return "Weak", COLOR_RED
    elif bits < 60:
        return "Fair", COLOR_YELLOW
    elif bits < 80:
        return "Strong", COLOR_GREEN
    elif bits < 128:
        return "Very Strong", COLOR_GREEN
    else:
        return "Excellent", COLOR_CYAN
def banner(text: str) -> None:
    """Print a centered section banner."""
    line = "─" * TERM_WIDTH
    print(f"\n{COLOR_CYAN}{line}{COLOR_RESET}")
    print(f"{COLOR_BOLD}{COLOR_CYAN}{text.center(TERM_WIDTH)}{COLOR_RESET}")
    print(f"{COLOR_CYAN}{line}{COLOR_RESET}")
def success(text: str) -> None:
    """Print a green success message."""
    print(f"{COLOR_GREEN}  ✔  {text}{COLOR_RESET}")
def error(text: str) -> None:
    """Print a red error message."""
    print(f"{COLOR_RED}  ✘  {text}{COLOR_RESET}")
def warn(text: str) -> None:
    """Print a yellow warning message."""
    print(f"{COLOR_YELLOW}  ⚠  {text}{COLOR_RESET}")
def info(text: str) -> None:
    """Print a cyan informational message."""
    print(f"{COLOR_CYAN}  ℹ  {text}{COLOR_RESET}")
def dim(text: str) -> None:
    """Print dimmed secondary text."""
    print(f"{COLOR_DIM}  {text}{COLOR_RESET}")
def divider() -> None:
    """Print a thin horizontal divider."""
    print(f"{COLOR_DIM}{'─' * TERM_WIDTH}{COLOR_RESET}")
def prompt(text: str) -> str:
    """Styled input prompt that returns stripped user input."""
    return input(f"{COLOR_BOLD}  ›  {text}{COLOR_RESET}").strip()
def confirm(text: str) -> bool:
    """Ask a yes/no question and return True if user answers yes."""
    answer = prompt(f"{text} [y/N]: ").lower()
    return answer in ("y", "yes")
