# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Version numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2025

### Added

#### Core Cryptography (`crypto.py`)
- AES-256-CBC encryption and decryption implemented from scratch (FIPS 197)
  - S-box and inverse S-box
  - SubBytes / InvSubBytes
  - ShiftRows / InvShiftRows
  - MixColumns / InvMixColumns using GF(2^8) arithmetic
  - AddRoundKey
  - Full 14-round key schedule for 256-bit keys (FIPS 197 §5.2)
  - PKCS#7 padding and unpadding with validation
- PBKDF2-SHA256 key derivation at 600,000 iterations via `hashlib.pbkdf2_hmac`
- HMAC-SHA256 computation and constant-time verification
- SHA-256 visualizer with round-by-round terminal output
  - Pre-processing and padding display
  - Message schedule W[0..63]
  - All 64 compression rounds with working variables a–h
  - Final digest verified against `hashlib`

#### Vault Storage (`vault.py`)
- Custom binary `.vault` file format (magic `PVLT`, versioned)
- Encrypted JSON payload (AES-256-CBC)
- HMAC-SHA256 integrity check stored in vault footer
- MAC-before-decrypt ordering (prevents padding oracle attacks)
- Fresh random IV on every save (prevents IV reuse)
- Atomic saves via temp-file-and-rename
- Salt persistence across saves (salt is fixed at vault creation)
- CRUD operations: add, list, search, update, delete entries
- Duplicate password detection
- Password age tracking
- Encrypted audit log of security events

#### Authentication & Session (`main.py`)
- Master password policy: 12+ characters, uppercase, digit required
- PBKDF2 key derivation with progress message
- Login lockout: 3 failed attempts triggers 30-second cooldown
- Lockout state persisted across process restarts (`.lockout` file)
- Session auto-lock after 5 minutes of inactivity
- Session key zeroed from memory on lock or quit
- Re-authentication flow after session timeout

#### Password Generator (`tools.py`)
- Cryptographically secure generation via `os.urandom()` + rejection sampling
- Configurable length (8–128 characters)
- Configurable character sets: lowercase, uppercase, digits, symbols
- Safe mode: excludes visually ambiguous characters (l, 1, O, 0, I)
- Shannon entropy calculation and visual strength bar
- Strength labels: Very Weak / Weak / Fair / Strong / Very Strong / Excellent

#### Security Auditor (`tools.py`)
- Password reuse detection (groups entries sharing the same password)
- Password age warnings (configurable threshold, default 90 days)
- Weak password scan (flags entries below 60 bits of entropy)

#### Bruteforce Simulator (`tools.py`)
- Compares SHA-256 (100M hashes/sec) vs PBKDF2-SHA256 (1 candidate/sec)
- Live animated attack counter using background thread
- Demo mode with 10 known weak passwords
- Custom password analysis mode

#### Installer (`install.py`)
- Self-contained: all five source files embedded as base64
- Python version check (3.10+ required)
- Cross-platform: Windows, macOS, Linux
- Platform-appropriate launcher (`run.bat` / `run.sh`)
- `--check` flag for verifying existing installations
- Custom installation directory via positional argument
- Import verification after file extraction

#### Infrastructure (`constants.py`)
- Single source of truth for all constants
- Custom exception hierarchy: `VaultError`, `VaultCorruptedError`, `VaultTamperedError`, `VaultNotFoundError`, `AuthenticationError`, `LockoutError`, `SessionExpiredError`, `PasswordPolicyError`
- ANSI colour terminal helpers
- `zero_bytes()` for secure memory wiping
- `constant_time_compare()` wrapping `hmac.compare_digest`
- `secure_random_bytes()` wrapping `os.urandom`
