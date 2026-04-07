
```
            ██████╗  █████╗ ███████╗███████╗██╗    ██╗ ██████╗ ██████╗ ██████╗
            ██╔══██╗██╔══██╗██╔════╝██╔════╝██║    ██║██╔═══██╗██╔══██╗██╔══██╗
            ██████╔╝███████║███████╗███████╗██║ █╗ ██║██║   ██║██████╔╝██║  ██║
            ██╔═══╝ ██╔══██║╚════██║╚════██║██║███╗██║██║   ██║██╔══██╗██║  ██║
            ██║     ██║  ██║███████║███████║╚███╔███╔╝╚██████╔╝██║  ██║██████╔╝
            ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝
```

<div align="center">

**A cryptographically serious CLI password manager - built in pure Python, from scratch, with zero dependencies.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)
[![Dependencies](https://img.shields.io/badge/Dependencies-None-f97316?style=flat-square)]()
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-8b5cf6?style=flat-square)]()
[![Standard](https://img.shields.io/badge/Crypto-FIPS%20197%20%7C%20NIST%20SP%20800--132-ef4444?style=flat-square)]()

[Installation](#installation) · [Usage](#usage) · [Security Design](#security-design) · [SHA-256 Visualizer](#sha-256-visualizer) · [Roadmap](#roadmap)

</div>

---

## What Makes This Different

Most password managers are black boxes. You trust that the library does the right thing, in the right order, with the right parameters - and you have no way to verify that it does.

This one is a glass box.

Every cryptographic primitive - AES-256 block cipher, PBKDF2 key derivation, HMAC-SHA256 integrity check, PKCS#7 padding, SHA-256 compression - is implemented from first principles, in readable Python, with comments that explain not just *what* the code does but *why* each decision was made. You can read from `main.py` all the way down to the GF(2⁸) field arithmetic in `crypto.py` and understand every step of the pipeline.

**This is Part 1 of 2.** The GUI edition (Part 2, Tkinter) is in active development and will share this exact cryptographic core without modification - zero code duplication between editions.

---

## Cryptographic Stack

| Primitive | Implementation | Standard | Purpose |
|---|---|---|---|
| **AES-256-CBC** | From scratch | FIPS 197 | Vault encryption |
| **PBKDF2-SHA256** | `hashlib.pbkdf2_hmac` | RFC 2898 / NIST SP 800-132 | Key derivation from master password |
| **HMAC-SHA256** | `hmac` stdlib | RFC 2104 | Vault integrity & tamper detection |
| **PKCS#7** | From scratch | RFC 5652 | AES block padding |
| **SHA-256** | From scratch | FIPS 180-4 | Visualizer & learning tool |
| **CSPRNG** | `os.urandom()` | OS-provided | All randomness — keys, salts, IVs |

> **600,000 PBKDF2 iterations** — the NIST SP 800-132 (2023) minimum. Each wrong master password guess costs an attacker ~0.6 seconds of CPU time. The bruteforce simulator built into the app shows exactly what that means in practice.

---

## Architecture

```
password-manager/
│
├── main.py        ← Entry point · CLI menus · auth · session lifecycle
├── crypto.py      ← AES-256 · PBKDF2 · HMAC · SHA-256 visualizer
├── vault.py       ← Binary .vault format · HMAC verification · audit log
├── tools.py       ← Password generator · security auditor · bruteforce sim
├── constants.py   ← Constants · exceptions · terminal helpers
│
└── install.py     ← Self-contained installer · zero pip · cross-platform
```

**The layers never bleed into each other.** `crypto.py` has no knowledge of the UI. `vault.py` has no knowledge of menus or sessions. `main.py` never touches raw bytes. This clean separation is why the GUI version can drop in the same core unchanged.

---

## Vault File Format

Every `.vault` file is a custom binary format designed from the ground up. No third-party container, no SQLite, no XML — a tight, versioned binary layout with a cryptographic integrity seal:

```
┌─────────────────────────────────────────────────────────────────────┐
│  Offset   Size   Field                                              │
│  ──────   ────   ────────────────────────────────────────────────  │
│    0        4    Magic bytes      b"PVLT"                           │
│    4        1    Version          0x01                              │
│    5       32    Salt             random, fixed at vault creation   │
│   37       16    IV               random, regenerated on every save │
│   53        4    Ciphertext len   uint32, big-endian                │
│   57        N    Ciphertext       AES-256-CBC encrypted JSON        │
│  57+N      32    HMAC-SHA256      over bytes [0 .. 57+N−1]         │
└─────────────────────────────────────────────────────────────────────┘
```

Three design decisions worth calling out:

- **The salt never changes.** Generated once at vault creation and stored in plaintext — this is correct. Salt is not a secret; it just needs to be unique per vault. Changing it would silently invalidate the derived key.
- **The IV is regenerated on every save.** IV reuse with the same key in CBC mode allows an attacker to XOR two ciphertexts and cancel the keystream, potentially leaking plaintext structure. The architecture makes reuse impossible.
- **HMAC is verified before decryption.** Not after — *before*. Decrypting unauthenticated ciphertext and checking integrity afterwards (Decrypt-then-MAC) opens a padding oracle attack surface. The vault refuses to pass a single byte to the AES decryptor until the HMAC is confirmed valid.

---

## Installation

### Option A — Single-file installer *(recommended)*

Download only `install.py`. It contains all five source files embedded as base64 and bootstraps the entire project without touching pip, virtualenvs, or your system Python packages:

```bash
python install.py
```

```
  [1/6]  Checking Python version
  ✔  Python 3.12.3  ✓

  [2/6]  Detecting platform
  ✔  OS          : Linux x86_64
  ✔  Python path : /usr/bin/python3

  [3/6]  Setting up installation directory
  ✔  Directory   : /home/user/password-manager

  [4/6]  Writing source files
  ✔  Wrote constants.py      (6.7 KB)
  ✔  Wrote crypto.py         (19.3 KB)
  ✔  Wrote vault.py          (10.5 KB)
  ✔  Wrote tools.py          (13.3 KB)
  ✔  Wrote main.py           (18.2 KB)

  [5/6]  Verifying imports
  ✔  import constants     ✓
  ✔  import crypto        ✓
  ✔  import vault         ✓
  ✔  import tools         ✓
  ✔  import main          ✓

  [6/6]  Creating launcher script
  ✔  Created launcher : run.sh  (chmod +x applied)
```

**Custom install path:**
```bash
python install.py ~/apps/my-vault
python install.py "C:\Users\you\vault"      # Windows
```

**Verify an existing installation at any time:**
```bash
python install.py --check
python install.py --check ~/apps/my-vault
```

### Option B — Git clone

```bash
git clone https://github.com/yourusername/password-manager.git
cd password-manager
python main.py
```

### Requirements

- **Python 3.10+** — no exceptions (uses structural type hints and union type syntax)
- **No external libraries** — if it is not in the Python standard library, it is not in this project

---

## Usage

```bash
# Default vault — creates my.vault in the current directory
python main.py

# Named vault in a custom location
python main.py work.vault
python main.py ~/secure/personal.vault
python main.py "C:\Users\you\Documents\vault.vault"
```

On first run you create a master password. The vault is encrypted and written to disk immediately. On every subsequent run, enter your master password to unlock it — each incorrect attempt triggers a full PBKDF2 derivation, so brute-forcing via the login prompt is computationally expensive by design.

### Main Menu

```
  ────────────────────────────────────────────────────────────────────────
  VAULT: my.vault  |  ENTRIES: 12  |  AUTO-LOCK: 5min
  ────────────────────────────────────────────────────────────────────────

  CREDENTIALS
    [1]  List all entries
    [2]  Search entries
    [3]  Add new entry
    [4]  Edit entry
    [5]  Delete entry

  TOOLS
    [6]  Password generator
    [7]  Security audit
    [8]  Bruteforce simulator
    [9]  SHA-256 hash visualizer

  SYSTEM
    [A]  View audit log
    [L]  Lock vault
    [Q]  Quit
```

---

## Feature Showcase

### 🔐 Add an Entry

```
  ────────────────────────────────────────────────────────────────────────
                                ADD ENTRY
  ────────────────────────────────────────────────────────────────────────
  ›  Site / Service name  : github.com
  ›  Username / Email     : alice@example.com
  ›  Generate a strong password automatically? [y/N]: y

    Generated Password:

    K#9mP$vR2@nX!qL7wZ&j

    Password Stats:
    Length  : 20 characters
    Entropy : 131.1 bits
    Strength: Excellent
    [████████████████████████████████████████]

  ✔  Entry [3] saved for github.com.
```

### 🔍 Security Auditor

```
  ────────────────────────────────────────────────────────────────────────
                          VAULT SECURITY AUDIT
  ────────────────────────────────────────────────────────────────────────
  Scanning 12 entries...

  [ CHECK 1 ] PASSWORD REUSE
  ⚠  Same password used across: twitter.com, instagram.com

  [ CHECK 2 ] PASSWORD AGE (>90 days)
  ⚠  facebook.com (alice@example.com) — last changed: 2024-08-12 14:33 UTC
  ⚠  amazon.com (alice@example.com)   — last changed: 2024-07-01 09:17 UTC

  [ CHECK 3 ] PASSWORD STRENGTH
  ⚠  reddit.com (alice@example.com) — Fair (44 bits)

  Audit complete.
  ⚠  4 issue(s) found. Review the warnings above.
```

### 💥 Bruteforce Simulator

```
  ────────────────────────────────────────────────────────────────────────
                          BRUTEFORCE SIMULATOR
  ────────────────────────────────────────────────────────────────────────

  WEAK PASSWORD CRACK TIME ESTIMATES

  Password        SHA-256 (fast)            PBKDF2-600k (secure)      Bits
  ──────────────────────────────────────────────────────────────────────────
  password        < 1 second                < 1 second                18
  123456          < 1 second                < 1 second                20
  letmein         < 1 second                4.8 minutes               34
  sunshine        < 1 second                1.9 hours                 37
  dragon          < 1 second                2.2 minutes               33

  Assumption: 100,000,000 SHA-256 hashes/sec, 1 PBKDF2 candidate/sec (single CPU).
  GPU farms can do 10,000× faster for SHA-256. PBKDF2 scales poorly on GPUs by design.
```

---

## SHA-256 Visualizer

Select **[9]** from the main menu to watch SHA-256 compute a digest in real time — every step of the FIPS 180-4 algorithm made visible:

```
  SHA-256 VISUALIZATION
  ────────────────────────────────────────────────────────────────────────
  INPUT TEXT  : 'hello'
  UTF-8 BYTES : 68 65 6C 6C 6F
  LENGTH      : 5 bytes = 40 bits

  [ STEP 1 ] PRE-PROCESSING & PADDING
  Append 0x80 bit, pad to 448 mod 512 bits, append 64-bit length.
  → 1 block(s) of 512 bits after padding

  BLOCK 0 (hex):
    68 65 6C 6C 6F 80 00 00  00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 28

  [ STEP 2 ] MESSAGE SCHEDULE (W[0..63])
  W[0..15] = block words. W[16..63] = sigma expansions.
    W[00]=68656C6C  W[01]=6F800000  W[02]=00000000  ...

  [ STEP 3 ] COMPRESSION — 64 ROUNDS
  Watching working variables (a..h) evolve each round.

   Rnd           a           b           c           d           e  ...
  ──────────────────────────────────────────────────────────────────────
     0  6A09E667  BB67AE85  3C6EF372  A54FF53A  510E527F  ...
     1  5D6AEBB1  6A09E667  BB67AE85  3C6EF372  9B0D3E6B  ...
     2  03BCF9AC  5D6AEBB1  6A09E667  BB67AE85  C87F98C1  ...
    ...

  [ STEP 4 ] ADD COMPRESSED CHUNK TO HASH VALUES
    H0 = 2CF24DBA   H1 = 5FB0A30E   H2 = 26925C1D  ...

  [ FINAL ] SHA-256 DIGEST
  2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
  ✔ Verified correct against Python hashlib
```

Three animation speeds: Fast (10ms/round), Normal (30ms/round), Slow (80ms/round).

The output is verified against `hashlib.sha256` on every run. If they ever disagree, the visualizer tells you explicitly.

---

## Security Design

### Why implement AES-256 from scratch instead of using a library?

Transparency. When you call `cryptography.hazmat.primitives.ciphers.Cipher(algorithms.AES(key), modes.CBC(iv))`, you are trusting that PyCA implemented AES correctly, that the mode is wired correctly, that padding is handled correctly, and that your installed version has no known vulnerabilities. All of that trust is invisible.

This project implements every AES operation in readable Python — the S-box lookup, the GF(2⁸) field arithmetic in MixColumns, the key schedule expansion, all 14 rounds of the cipher. A reviewer can read `crypto.py` from top to bottom and verify every step against FIPS 197 directly. The tradeoff is performance; the gain is complete auditability.

### Why PBKDF2 at 600,000 iterations?

NIST Special Publication 800-132 (2023) specifies 600,000 as the minimum iteration count for PBKDF2-HMAC-SHA256 used for password hashing. This is calibrated so that a single password guess costs approximately 0.6 seconds of CPU time on contemporary hardware.

The practical consequence: an attacker with one million candidate passwords needs ~7 days of single-core CPU time to exhaust them. PBKDF2 also resists GPU acceleration — SHA-256 runs at ~10 billion hashes/second on a high-end GPU cluster, but PBKDF2's serial dependency chain does not parallelize effectively, limiting GPU advantage to roughly 10,000× rather than the 100,000× you'd see with a bare hash.

### Why verify the HMAC before decrypting?

This is the most subtle security decision in the codebase.

A **padding oracle attack** works by sending a modified ciphertext to the decryptor and observing whether it returns a "wrong padding" error or a "wrong data" error. Those two error types reveal a single bit of information — and with enough queries, that single bit is sufficient to recover the entire plaintext without ever knowing the key.

The defense is authentication before decryption. If the HMAC over the ciphertext is verified first, any modified ciphertext is rejected before the padding check runs. No padding information leaks because the decryptor is never reached. `load_vault()` enforces this strictly: the HMAC check runs first, and `aes_decrypt_cbc()` is only called if the HMAC is valid. The order is a security requirement, not a convention.

### Why rejection sampling in the password generator?

Consider generating a random character from a 95-character charset using a random byte. The naive approach — `charset[byte % 95]` — has a bias problem: 256 is not evenly divisible by 95. The first 66 characters of the charset appear in the mapping three times while the remaining 29 appear only twice, making them ~50% more likely to appear in generated passwords.

The fix is rejection sampling: any byte ≥ `256 - (256 % charset_size)` is discarded and a new byte is drawn. The accepted range is exactly divisible by the charset size, giving a perfectly uniform distribution. The expected overhead is less than 0.1 extra bytes drawn per character.

### Why zero the key in memory?

Python's garbage collector reclaims memory at an unspecified time and does not zero it before returning it to the allocator. A `bytes` object holding your AES key could persist in memory for seconds, minutes, or indefinitely after you `del` it.

The session key is stored in a `bytearray` (mutable, unlike `bytes`) and explicitly overwritten byte-by-byte with zeros before the reference is released. This happens in `zero_bytes()` → called by `Session.lock()` and `Session.close()`. After zeroing, a memory dump of the Python process finds zeros where the key was, not key material. This is best-effort — not a guarantee against swap, CPU caches, or allocator internals — but it reduces the key exposure window significantly compared to doing nothing.

---

## Runtime Files

| File | Contents | Safe to back up? |
|---|---|---|
| `my.vault` | AES-256-CBC encrypted credential database | ✅ Yes — useless without the master password |
| `.audit.log` | Timestamped log: logins, saves, lockouts | ✅ Yes — metadata only, no passwords |
| `.lockout` | Failed attempt count and last-attempt timestamp | No — local state only |

**Back up your `.vault` file.** It is the only copy of your credentials. If it is lost, there is no recovery. The encryption is strong enough that a stolen vault file is useless to an attacker without the master password.

None of these files ever contain a plaintext password, a key, or raw key material.

---

## Limitations

| Limitation | Detail |
|---|---|
| **Single-device** | No sync, no cloud, no sharing — the vault file lives on one machine |
| **No password recovery** | Forgotten master password = locked vault, permanently. No backdoor, no recovery email, no security questions. |
| **Not side-channel hardened** | Python integers are not constant-time at the CPU level. This implementation is educational, not hardened against cache-timing or power analysis. |
| **No GUI** | CLI only in this edition. Part 2 (Tkinter) is in development. |

---

## Roadmap

- [x] CLI edition with full cryptographic core
- [x] Self-contained cross-platform installer (`install.py`)
- [ ] **Part 2: GUI** — Tkinter wrapper, same crypto/vault core, zero code duplication
- [ ] Vault export to encrypted CSV / JSON
- [ ] Vault backup with automatic versioning
- [ ] TOTP (2FA code) generation and display
- [ ] Multi-vault support (switch between vaults without restarting)
- [ ] Argon2id as an alternative KDF (stronger memory-hardness than PBKDF2)

---

## Standards & References

| Document | Relevance |
|---|---|
| [FIPS 197](https://csrc.nist.gov/publications/detail/fips/197/final) | AES specification — implemented in `crypto.py` |
| [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final) | SHA-256 specification — visualized in `crypto.py` |
| [NIST SP 800-132](https://csrc.nist.gov/publications/detail/sp/800-132/final) | PBKDF2 iteration count recommendation |
| [RFC 2898](https://www.rfc-editor.org/rfc/rfc2898) | PKCS #5: PBKDF2 specification |
| [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104) | HMAC specification |
| [RFC 5652](https://www.rfc-editor.org/rfc/rfc5652) | PKCS#7 padding specification |

---

## License

[MIT](LICENSE) © 2025

---

<div align="center">

*Built to be read, not just run.*

</div>
