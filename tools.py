# tools.py >>> password generator, vault auditor, bruteforce simulator
import string
import time
import threading
from constants import (
    MIN_GEN_LENGTH, MAX_GEN_LENGTH, DEFAULT_GEN_LENGTH, PASSWORD_AGE_WARN,
    PBKDF2_ITERATIONS,
    COLOR_RESET, COLOR_RED, COLOR_GREEN, COLOR_YELLOW,
    COLOR_BOLD, COLOR_DIM, TERM_WIDTH,
    secure_random_bytes, entropy_bits, strength_label,
    banner, success, warn, error, info, divider, prompt, confirm
)
from vault import (
    list_entries, get_duplicate_passwords, get_old_passwords
)
# CHARACTER SETS FOR PASSWORD GENERATION
CHARSET_LOWER   = string.ascii_lowercase            # a-z
CHARSET_UPPER   = string.ascii_uppercase            # A-Z
CHARSET_DIGITS  = string.digits                     # 0-9
CHARSET_SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?"    # Common safe symbols
CHARSET_SAFE = (
    "abcdefghjkmnpqrstuvwxyz"
    "ABCDEFGHJKMNPQRSTUVWXYZ"
    "23456789"
    "!@#$%^&*-_=+?"
)
# PASSWORD GENERATOR
def generate_password(
    length:      int  = DEFAULT_GEN_LENGTH,
    use_upper:   bool = True,
    use_digits:  bool = True,
    use_symbols: bool = True,
    safe_mode:   bool = False
) -> str:
    """
    Generate a cryptographically secure random password.

    Uses os.urandom() as the source of randomness - NOT random.random(),
    which is a PRNG unsuitable for security purposes.

    The rejection-sampling approach ensures each character is chosen
    with exactly equal probability (no modulo bias).

    Args:
        length:      Number of characters in the generated password.
        use_upper:   Include uppercase letters.
        use_digits:  Include digits.
        use_symbols: Include symbol characters.
        safe_mode:   Use only unambiguous characters (no l/1/O/0/I).

    Returns:
        A random password string of the requested length.
    """
    if length < MIN_GEN_LENGTH or length > MAX_GEN_LENGTH:
        raise ValueError(f"Length must be between {MIN_GEN_LENGTH} and {MAX_GEN_LENGTH}.")
    if safe_mode:
        charset = CHARSET_SAFE
    else:
        charset = CHARSET_LOWER
        if use_upper:   charset += CHARSET_UPPER
        if use_digits:  charset += CHARSET_DIGITS
        if use_symbols: charset += CHARSET_SYMBOLS
    charset_size = len(charset)
    max_valid = 256 - (256 % charset_size)
    password  = []
    while len(password) < length:
        raw = secure_random_bytes(length * 2)
        for byte in raw:
            if byte < max_valid:
                password.append(charset[byte % charset_size])
            if len(password) == length:
                break
    result = "".join(password)
    checks = [CHARSET_LOWER]
    if use_upper and not safe_mode:   checks.append(CHARSET_UPPER)
    if use_digits and not safe_mode:  checks.append(CHARSET_DIGITS)
    if use_symbols and not safe_mode: checks.append(CHARSET_SYMBOLS)
    if not safe_mode:
        for charset_check in checks:
            if not any(c in charset_check for c in result):
                return generate_password(length, use_upper, use_digits, use_symbols, safe_mode)
    return result
def password_entropy(password: str) -> float:
    """
    Estimate the entropy of an existing password string.
    Detects which character classes are present and calculates
    entropy based on the effective alphabet size.
    """
    has_lower = any(c in CHARSET_LOWER   for c in password)
    has_upper = any(c in CHARSET_UPPER   for c in password)
    has_digit = any(c in CHARSET_DIGITS  for c in password)
    has_symbol = any(c in CHARSET_SYMBOLS for c in password)
    charset_size = 0
    if has_lower: charset_size += len(CHARSET_LOWER)
    if has_upper: charset_size += len(CHARSET_UPPER)
    if has_digit: charset_size += len(CHARSET_DIGITS)
    if has_symbol: charset_size += len(CHARSET_SYMBOLS)
    if charset_size == 0:
        charset_size = 26
    return entropy_bits(len(password), charset_size)
def print_password_stats(password: str, charset_size: int = None) -> None:
    """
    Print entropy score and strength label for a password.
    """
    bits   = password_entropy(password)
    label, color = strength_label(bits)
    print(f"\n  {COLOR_BOLD}Password Stats:{COLOR_RESET}")
    print(f"  Length  : {len(password)} characters")
    print(f"  Entropy : {bits:.1f} bits")
    print(f"  Strength: {color}{label}{COLOR_RESET}")
    bar_filled = min(int(bits / 2), TERM_WIDTH - 20)
    bar_empty  = max(0, 40 - bar_filled)
    bar = f"  [{color}{'█' * bar_filled}{COLOR_DIM}{'░' * bar_empty}{COLOR_RESET}]"
    print(bar)
def interactive_generator() -> str | None:
    """
    Interactive CLI for password generation.
    Walks the user through options and displays the result.
    Returns the generated password, or None if user cancels.
    """
    banner("PASSWORD GENERATOR")
    try:
        raw_len = prompt(f"Password length [{DEFAULT_GEN_LENGTH}]: ")
        length  = int(raw_len) if raw_len else DEFAULT_GEN_LENGTH
    except ValueError:
        error("Invalid length. Using default.")
        length = DEFAULT_GEN_LENGTH
    safe_mode   = confirm("Avoid ambiguous characters (l/1/O/0)? ")
    use_upper   = not safe_mode and confirm("Include uppercase letters? ")
    use_digits  = not safe_mode and confirm("Include digits? ")
    use_symbols = not safe_mode and confirm("Include symbols? ")
    try:
        password = generate_password(
            length      = length,
            use_upper   = use_upper if not safe_mode else True,
            use_digits  = use_digits if not safe_mode else True,
            use_symbols = use_symbols if not safe_mode else True,
            safe_mode   = safe_mode
        )
    except ValueError as e:
        error(str(e))
        return None
    print(f"\n  {COLOR_BOLD}Generated Password:{COLOR_RESET}")
    print(f"\n  {COLOR_GREEN}{COLOR_BOLD}{password}{COLOR_RESET}\n")
    print_password_stats(password)
    if confirm("\n  Generate another?"):
        return interactive_generator()
    return password
# VAULT AUDITOR
def audit_vault(payload: dict) -> None:
    """
    Scan the entire vault for security issues and print a report.

    Checks:
    - Duplicate passwords (reuse)
    - Old passwords (over PASSWORD_AGE_WARN days)
    - Weak passwords (low entropy)
    """
    banner("VAULT SECURITY AUDIT")
    entries = list_entries(payload)
    if not entries:
        info("Vault is empty — nothing to audit.")
        return
    print(f"  Scanning {len(entries)} entries...\n")
    issues_found = 0
    print(f"{COLOR_BOLD}  [ CHECK 1 ] PASSWORD REUSE{COLOR_RESET}")
    duplicates = get_duplicate_passwords(payload)
    if duplicates:
        for group in duplicates:
            sites = ", ".join(e["site"] for e in group)
            warn(f"Same password used across: {sites}")
            issues_found += 1
    else:
        success("No password reuse detected.")
    divider()
    print(f"{COLOR_BOLD}  [ CHECK 2 ] PASSWORD AGE (>{PASSWORD_AGE_WARN} days){COLOR_RESET}")
    old = get_old_passwords(payload, PASSWORD_AGE_WARN)
    if old:
        for entry in old:
            from constants import format_timestamp
            last_changed = format_timestamp(entry.get("modified", 0))
            warn(f"{entry['site']} ({entry['username']}) — last changed: {last_changed}")
            issues_found += 1
    else:
        success(f"All passwords changed within the last {PASSWORD_AGE_WARN} days.")
    divider()
    print(f"{COLOR_BOLD}  [ CHECK 3 ] PASSWORD STRENGTH{COLOR_RESET}")
    weak_found = False
    for entry in entries:
        bits = password_entropy(entry["password"])
        label, color  = strength_label(bits)
        if bits < 60:
            warn(f"{entry['site']} ({entry['username']}) — {color}{label}{COLOR_RESET} ({bits:.0f} bits)")
            issues_found += 1
            weak_found = True
    if not weak_found:
        success("All passwords meet minimum strength requirements.")
    divider()
    print(f"\n  {COLOR_BOLD}Audit complete.{COLOR_RESET}")
    if issues_found == 0:
        success("No issues found. Your vault is in excellent shape.")
    else:
        warn(f"{issues_found} issue(s) found. Review the warnings above.")
# estimated hashes per second (conservative CPU estimates)
SHA256_HASHES_PER_SEC = 100_000_000   # ~100M/s on a modern CPU (single core)
PBKDF2_HASHES_PER_SEC = 1             # PBKDF2 600k iters ≈ 1 candidate/sec on CPU
DEMO_WEAK_PASSWORDS = [
    "password", "123456", "admin", "letmein", "qwerty",
    "monkey", "dragon", "master", "sunshine", "welcome",
]
def _simulate_crack_time(password: str, hashes_per_sec: int) -> str:
    """
    Estimate time to crack a password by exhaustive search
    at a given hash rate.

    Formula: average attempts = (charset_size ^ length) / 2
    """
    import math
    bits   = password_entropy(password)
    search = (2 ** bits) / 2
    seconds = search / hashes_per_sec
    if seconds < 1:
        return "< 1 second"
    elif seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.1f} hours"
    elif seconds < 86400 * 365:
        return f"{seconds/86400:.1f} days"
    elif seconds < 86400 * 365 * 1000:
        return f"{seconds/(86400*365):.1f} years"
    else:
        return f"{seconds/(86400*365):.2e} years"
def _animate_crack_attempt(
    password: str,
    hashes_per_sec: int,
    label: str,
    color: str,
    stop_event: threading.Event
) -> None:
    """
    Background thread: animate a live 'cracking' counter for visual effect.
    Counts attempts and shows elapsed time until stop_event is set.
    """
    start = time.time()
    attempts = 0
    while not stop_event.is_set():
        elapsed = time.time() - start
        attempts = int(elapsed * hashes_per_sec)
        print(
            f"\r  {color}{label}{COLOR_RESET}  "
            f"Attempts: {attempts:>15,}  |  "
            f"Elapsed: {elapsed:>6.1f}s",
            end="", flush=True
        )
        time.sleep(0.1)
    print()
def run_bruteforce_simulator() -> None:
    """
    Interactive bruteforce simulation comparing SHA-256 vs PBKDF2-SHA256.

    Shows:
    - How fast SHA-256 can be brute-forced
    - How PBKDF2's intentional slowness provides protection
    - Concrete time estimates for the user's chosen password
    """
    banner("BRUTEFORCE SIMULATOR")
    print(f"""
  {COLOR_DIM}This simulator shows how password hashing schemes resist brute-force.
  It compares plain SHA-256 (fast, dangerous) vs PBKDF2-SHA256 (slow, safe).
  No real cracking occurs — this is an educational timing demonstration.{COLOR_RESET}
""")
    choice = prompt("(1) Test a custom password  (2) Demo with weak passwords  [1/2]: ")
    if choice == "2":
        _demo_weak_passwords()
    else:
        _demo_custom_password()
def _demo_weak_passwords() -> None:
    """Show crack time estimates for a list of known weak passwords."""
    print(f"\n  {COLOR_BOLD}WEAK PASSWORD CRACK TIME ESTIMATES{COLOR_RESET}\n")
    print(f"  {'Password':<15} {'SHA-256 (fast)':<25} {'PBKDF2-600k (secure)':<25} {'Bits'}")
    print(f"  {COLOR_DIM}{'─'*70}{COLOR_RESET}")
    for pw in DEMO_WEAK_PASSWORDS:
        bits        = password_entropy(pw)
        sha_time    = _simulate_crack_time(pw, SHA256_HASHES_PER_SEC)
        pbkdf2_time = _simulate_crack_time(pw, PBKDF2_HASHES_PER_SEC)
        _, color    = strength_label(bits)
        print(
            f"  {pw:<15} "
            f"{COLOR_RED}{sha_time:<25}{COLOR_RESET} "
            f"{COLOR_YELLOW}{pbkdf2_time:<25}{COLOR_RESET} "
            f"{color}{bits:.0f}{COLOR_RESET}"
        )
    print(f"\n  {COLOR_DIM}Assumption: {SHA256_HASHES_PER_SEC:,} SHA-256 hashes/sec, "
          f"{PBKDF2_HASHES_PER_SEC} PBKDF2 candidates/sec (single CPU core).{COLOR_RESET}")
    print(f"  {COLOR_DIM}GPU farms can do 10,000x faster for SHA-256. "
          f"PBKDF2 scales poorly on GPUs by design.{COLOR_RESET}")
def _demo_custom_password() -> None:
    """Animate a bruteforce attempt on a user-supplied password."""
    import getpass as gp
    pw = gp.getpass("  Enter a password to analyse (not stored): ")
    if not pw:
        error("No password entered.")
        return
    bits  = password_entropy(pw)
    label, color = strength_label(bits)
    sha_time = _simulate_crack_time(pw, SHA256_HASHES_PER_SEC)
    pbkdf2_time = _simulate_crack_time(pw, PBKDF2_HASHES_PER_SEC)
    print_password_stats(pw)
    print(f"\n  {COLOR_BOLD}ESTIMATED CRACK TIME:{COLOR_RESET}")
    print(f"  SHA-256 (plain, fast)      : {COLOR_RED}{sha_time}{COLOR_RESET}")
    print(f"  PBKDF2-SHA256 (600k iters) : {COLOR_GREEN}{pbkdf2_time}{COLOR_RESET}")
    if bits < 60:
        print(f"\n  {COLOR_YELLOW}Simulating SHA-256 attack for 3 seconds...{COLOR_RESET}")
        stop = threading.Event()
        t = threading.Thread(
            target=_animate_crack_attempt,
            args=(pw, SHA256_HASHES_PER_SEC, "SHA-256  ", COLOR_RED, stop),
            daemon=True
        )
        t.start()
        time.sleep(3)
        stop.set()
        t.join()
        print(f"  {COLOR_RED}That many attempts in 3 seconds — and we haven't even tried yet.{COLOR_RESET}")
    else:
        print(f"\n  {COLOR_GREEN}This password would take {pbkdf2_time} to crack with PBKDF2.{COLOR_RESET}")
        print(f"  {COLOR_DIM}Even a nation-state attacker would give up.{COLOR_RESET}")
    print(f"\n  {COLOR_DIM}Key insight: PBKDF2 turns a millisecond SHA-256 check into ~0.6 seconds.")
    print(f"  That 600x slowdown is intentional. It's the entire point.{COLOR_RESET}")
