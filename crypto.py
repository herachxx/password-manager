# crypto.py >>> AES-256 (CBC mode), SHA-256 visualizer, PBKDF2 key derivation
# implementing these cryptographic primitives from scratch:
#   1. AES-256 encryption/decryption (FIPS 197)
#   2. PBKDF2-SHA256 key derivation  (RFC 2898)
#   3. SHA-256 round-by-round visualizer (FIPS 180-4)
import hashlib
import hmac as hmac_module
import time
from constants import (
    AES_KEY_SIZE, AES_BLOCK_SIZE, PBKDF2_ITERATIONS, PBKDF2_HASH,
    COLOR_CYAN, COLOR_YELLOW, COLOR_GREEN, COLOR_DIM, COLOR_RESET,
    COLOR_BOLD, COLOR_RED
)
# S-Box (Substitution Box)
_SBOX = [
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16,
]
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_RCON = [
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36,
    0x6C,0xD8,0xAB,0x4D,0x9A,0x2F,0x5E,0xBC,0x63,0xC6,
]
def _xtime(b: int) -> int:
    """
    Multiply byte b by 2 in GF(2^8).
    If the high bit is set, XOR with 0x1B (the AES irreducible polynomial).
    This is the fundamental operation for MixColumns.
    """
    return ((b << 1) ^ 0x1B) & 0xFF if (b & 0x80) else (b << 1) & 0xFF
def _gmul(a: int, b: int) -> int:
    """
    Multiply two bytes in GF(2^8) using the Russian peasant algorithm.
    Used in MixColumns for matrix multiplication over the finite field.
    """
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return result
def _sub_bytes(state: list[list[int]]) -> list[list[int]]:
    """
    SubBytes: replace each byte with its S-box value.
    Provides non-linearity — the only non-linear step in AES.
    """
    return [[_SBOX[state[r][c]] for c in range(4)] for r in range(4)]
def _inv_sub_bytes(state: list[list[int]]) -> list[list[int]]:
    """Inverse SubBytes using the inverse S-box (for decryption)."""
    return [[_INV_SBOX[state[r][c]] for c in range(4)] for r in range(4)]
def _shift_rows(state: list[list[int]]) -> list[list[int]]:
    """
    ShiftRows: cyclically shift row r left by r positions.
    Row 0: no shift. Row 1: shift 1. Row 2: shift 2. Row 3: shift 3.
    Ensures bytes from each column spread to different columns after MixColumns.
    """
    return [
        [state[r][(c + r) % 4] for c in range(4)]
        for r in range(4)
    ]
def _inv_shift_rows(state: list[list[int]]) -> list[list[int]]:
    """Inverse ShiftRows: shift row r right by r positions (for decryption)."""
    return [
        [state[r][(c - r) % 4] for c in range(4)]
        for r in range(4)
    ]
def _mix_columns(state: list[list[int]]) -> list[list[int]]:
    """
    MixColumns: treat each column as a polynomial over GF(2^8),
    multiply by a fixed matrix [2,3,1,1 / 1,2,3,1 / 1,1,2,3 / 3,1,1,2].
    Provides diffusion — each output byte depends on all 4 input bytes.
    """
    new_state = [[0] * 4 for _ in range(4)]
    for c in range(4):
        s = [state[r][c] for r in range(4)]
        new_state[0][c] = _gmul(s[0],2)^_gmul(s[1],3)^s[2]^s[3]
        new_state[1][c] = s[0]^_gmul(s[1],2)^_gmul(s[2],3)^s[3]
        new_state[2][c] = s[0]^s[1]^_gmul(s[2],2)^_gmul(s[3],3)
        new_state[3][c] = _gmul(s[0],3)^s[1]^s[2]^_gmul(s[3],2)
    return new_state
def _inv_mix_columns(state: list[list[int]]) -> list[list[int]]:
    """Inverse MixColumns using the inverse matrix (for decryption)."""
    new_state = [[0] * 4 for _ in range(4)]
    for c in range(4):
        s = [state[r][c] for r in range(4)]
        new_state[0][c] = _gmul(s[0],14)^_gmul(s[1],11)^_gmul(s[2],13)^_gmul(s[3],9)
        new_state[1][c] = _gmul(s[0],9)^_gmul(s[1],14)^_gmul(s[2],11)^_gmul(s[3],13)
        new_state[2][c] = _gmul(s[0],13)^_gmul(s[1],9)^_gmul(s[2],14)^_gmul(s[3],11)
        new_state[3][c] = _gmul(s[0],11)^_gmul(s[1],13)^_gmul(s[2],9)^_gmul(s[3],14)
    return new_state
def _add_round_key(state: list[list[int]], round_key: list[int]) -> list[list[int]]:
    """
    AddRoundKey: XOR each state byte with the corresponding round key byte.
    The only step that uses the key. XOR is its own inverse, so same for decrypt.
    """
    return [
        [state[r][c] ^ round_key[r + 4 * c] for c in range(4)]
        for r in range(4)
    ]
def _key_schedule(key: bytes) -> list[list[int]]:
    """
    AES-256 Key Expansion (FIPS 197 Section 5.2).
    Expands a 32-byte key into 15 round keys of 16 bytes each (240 bytes total).
    AES-256 = 14 rounds + 1 initial = 15 round keys.
    """
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4*i:4*i+4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // nk]
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[b] for b in temp]
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
    round_keys = []
    for i in range(nr + 1):
        rk = []
        for j in range(4):
            rk.extend(w[4 * i + j])
        round_keys.append(rk)
    return round_keys
def _bytes_to_state(block: bytes) -> list[list[int]]:
    """Convert a 16-byte block to AES's column-major 4×4 state matrix."""
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]
def _state_to_bytes(state: list[list[int]]) -> bytes:
    """Convert a 4×4 AES state matrix back to a 16-byte block."""
    return bytes(state[r][c] for c in range(4) for r in range(4))
def _aes_encrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    """
    Encrypt a single 16-byte AES block through all 14 rounds.
    Round 0:         AddRoundKey only
    Rounds 1–13:     SubBytes → ShiftRows → MixColumns → AddRoundKey
    Round 14 (final): SubBytes → ShiftRows → AddRoundKey (no MixColumns)
    """
    nr = len(round_keys) - 1
    state = _bytes_to_state(block)
    state = _add_round_key(state, round_keys[0])
    for rnd in range(1, nr + 1):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        if rnd < nr:
            state = _mix_columns(state)
        state = _add_round_key(state, round_keys[rnd])
    return _state_to_bytes(state)
def _aes_decrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    """
    Decrypt a single 16-byte AES block (inverse of _aes_encrypt_block).
    Applies inverse operations in reverse order.
    """
    nr = len(round_keys) - 1
    state = _bytes_to_state(block)
    state = _add_round_key(state, round_keys[nr])
    for rnd in range(nr - 1, -1, -1):
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, round_keys[rnd])
        if rnd > 0:
            state = _inv_mix_columns(state)
    return _state_to_bytes(state)
def _pkcs7_pad(data: bytes) -> bytes:
    """
    PKCS#7 padding: append N bytes each with value N,
    where N = block_size - (len(data) % block_size).
    If data is already block-aligned, add a full padding block.
    This ensures the decryptor always knows how much padding to remove.
    """
    pad_len = AES_BLOCK_SIZE - (len(data) % AES_BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)
def _pkcs7_unpad(data: bytes) -> bytes:
    """
    Remove PKCS#7 padding. Validates that all padding bytes are correct.
    Raises ValueError on invalid padding to prevent padding oracle attacks.
    """
    if not data:
        raise ValueError("Empty data cannot be unpadded.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > AES_BLOCK_SIZE:
        raise ValueError("Invalid PKCS#7 padding length.")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS#7 padding bytes.")
    return data[:-pad_len]
def aes_encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    AES-256-CBC encryption.

    CBC (Cipher Block Chaining): each plaintext block is XORed with the
    previous ciphertext block before encryption. The IV acts as the
    'previous block' for the first block. This ensures identical plaintext
    blocks produce different ciphertext blocks (unlike ECB mode).

    Args:
        plaintext: Raw bytes to encrypt (any length).
        key:       32-byte AES-256 key.
        iv:        16-byte random initialization vector (must be unique per encryption).

    Returns:
        Ciphertext bytes (same length as padded plaintext).
    """
    assert len(key) == AES_KEY_SIZE,  f"Key must be {AES_KEY_SIZE} bytes."
    assert len(iv)  == AES_BLOCK_SIZE, f"IV must be {AES_BLOCK_SIZE} bytes."
    round_keys = _key_schedule(key)
    padded = _pkcs7_pad(plaintext)
    ciphertext = b""
    prev_block = iv
    for i in range(0, len(padded), AES_BLOCK_SIZE):
        block = bytes(a ^ b for a, b in zip(padded[i:i+AES_BLOCK_SIZE], prev_block))
        enc = _aes_encrypt_block(block, round_keys)
        ciphertext += enc
        prev_block = enc
    return ciphertext
def aes_decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    AES-256-CBC decryption.

    Args:
        ciphertext: Encrypted bytes (must be a multiple of 16).
        key:        32-byte AES-256 key (must match encryption key).
        iv:         16-byte IV used during encryption.

    Returns:
        Original plaintext bytes with padding removed.
    """
    assert len(key) == AES_KEY_SIZE,  f"Key must be {AES_KEY_SIZE} bytes."
    assert len(iv)  == AES_BLOCK_SIZE, f"IV must be {AES_BLOCK_SIZE} bytes."
    assert len(ciphertext) % AES_BLOCK_SIZE == 0, "Ciphertext length not a multiple of block size."
    round_keys = _key_schedule(key)
    plaintext  = b""
    prev_block = iv
    for i in range(0, len(ciphertext), AES_BLOCK_SIZE):
        block      = ciphertext[i:i+AES_BLOCK_SIZE]
        dec        = _aes_decrypt_block(block, round_keys)
        plaintext += bytes(a ^ b for a, b in zip(dec, prev_block))
        prev_block = block
    return _pkcs7_unpad(plaintext)
def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from a master password using PBKDF2-SHA256.

    PBKDF2 (Password-Based Key Derivation Function 2, RFC 2898) applies
    the HMAC-SHA256 pseudorandom function PBKDF2_ITERATIONS times.
    The high iteration count makes brute-force attacks computationally expensive:
    an attacker must perform 600,000 SHA-256 operations per guess.

    Args:
        password: The master password string (UTF-8 encoded).
        salt:     A random 32-byte salt (unique per vault, stored in vault file).

    Returns:
        A 32-byte key suitable for AES-256.
    """
    return hashlib.pbkdf2_hmac(
        hash_name = PBKDF2_HASH,
        password = password.encode("utf-8"),
        salt = salt,
        iterations = PBKDF2_ITERATIONS,
        dklen = AES_KEY_SIZE
    )
def compute_hmac(key: bytes, data: bytes) -> bytes:
    """
    Compute HMAC-SHA256 over data using key.

    HMAC provides authenticated encryption — it detects tampering.
    We compute HMAC over the ciphertext (Encrypt-then-MAC pattern),
    which must be verified BEFORE decryption to prevent padding oracle attacks.

    Args:
        key:  32-byte key (should be a separate key from the encryption key,
              or the same key is acceptable when using PBKDF2 with high iterations).
        data: The ciphertext bytes to authenticate.

    Returns:
        32-byte HMAC-SHA256 digest.
    """
    return hmac_module.new(key, data, hashlib.sha256).digest()
def verify_hmac(key: bytes, data: bytes, expected_hmac: bytes) -> bool:
    """
    Verify HMAC in constant time.
    Returns True if valid, False if tampered.
    Uses hmac.compare_digest to prevent timing attacks.
    """
    actual = compute_hmac(key, data)
    return hmac_module.compare_digest(actual, expected_hmac)
_SHA256_H0 = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
]
_SHA256_K = [
    0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,
    0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,
    0xE49B69C1,0xEFBE4786,0x0FC19DC6,0x240CA1CC,0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,
    0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,0xC6E00BF3,0xD5A79147,0x06CA6351,0x14292967,
    0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,
    0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,0xD192E819,0xD6990624,0xF40E3585,0x106AA070,
    0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,
    0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2,
]
def _rotr32(x: int, n: int) -> int:
    """Rotate right a 32-bit integer x by n bits."""
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
def _sha256_preprocess(message: bytes) -> list[bytes]:
    """
    SHA-256 Pre-processing (FIPS 180-4 Section 5.1.1):
    1. Append bit '1' (byte 0x80)
    2. Append zeros until message length ≡ 448 (mod 512) bits
    3. Append original message length as 64-bit big-endian integer
    Returns a list of 64-byte (512-bit) message blocks.
    """
    msg = bytearray(message)
    bit_len = len(message) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0x00)
    msg += bit_len.to_bytes(8, "big")
    return [bytes(msg[i:i+64]) for i in range(0, len(msg), 64)]
def _sha256_message_schedule(block: bytes) -> list[int]:
    """
    Build the 64-word message schedule W from a 512-bit block.
    W[0..15]  = the 16 32-bit words of the block
    W[16..63] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16]
    The sigma functions provide diffusion across the schedule.
    """
    W = list(int.from_bytes(block[i:i+4], "big") for i in range(0, 64, 4))
    for i in range(16, 64):
        s0 = _rotr32(W[i-15], 7) ^ _rotr32(W[i-15], 18) ^ (W[i-15] >> 3)
        s1 = _rotr32(W[i-2], 17) ^ _rotr32(W[i-2],  19) ^ (W[i-2]  >> 10)
        W.append((W[i-16] + s0 + W[i-7] + s1) & 0xFFFFFFFF)
    return W
def visualize_sha256(text: str, delay: float = 0.03) -> str:
    """
    Compute SHA-256 with a full round-by-round terminal visualization.

    Shows:
    - UTF-8 bytes of input
    - Binary padding and block structure
    - Message schedule construction
    - All 64 compression rounds with working variables
    - Final digest assembly

    Args:
        text:  The string to hash.
        delay: Seconds to pause between rounds (for animation effect).

    Returns:
        The final SHA-256 hex digest string.
    """
    message = text.encode("utf-8")
    print(f"\n{COLOR_BOLD}{COLOR_CYAN}  SHA-256 VISUALIZATION{COLOR_RESET}")
    print(f"{COLOR_DIM}  {'─' * 68}{COLOR_RESET}")
    print(f"{COLOR_CYAN}  INPUT TEXT  {COLOR_RESET}: {repr(text)}")
    hex_bytes = " ".join(f"{b:02X}" for b in message)
    print(f"{COLOR_CYAN}  UTF-8 BYTES {COLOR_RESET}: {hex_bytes}")
    print(f"{COLOR_CYAN}  LENGTH      {COLOR_RESET}: {len(message)} bytes = {len(message)*8} bits")
    print(f"\n{COLOR_BOLD}  [ STEP 1 ] PRE-PROCESSING & PADDING{COLOR_RESET}")
    print(f"{COLOR_DIM}  Append 0x80 bit, pad to 448 mod 512 bits, append 64-bit length.{COLOR_RESET}")
    blocks = _sha256_preprocess(message)
    print(f"  → {len(blocks)} block(s) of 512 bits after padding")
    for bi, block in enumerate(blocks):
        print(f"\n{COLOR_YELLOW}  BLOCK {bi} (hex):{COLOR_RESET}")
        for row in range(4):
            segment = block[row*16:(row+1)*16]
            print(f"    {' '.join(f'{b:02X}' for b in segment)}")
    print(f"\n{COLOR_BOLD}  [ STEP 2 ] MESSAGE SCHEDULE (W[0..63]) — Block 0{COLOR_RESET}")
    print(f"{COLOR_DIM}  W[0..15] = block words. W[16..63] = sigma expansions.{COLOR_RESET}")
    W = _sha256_message_schedule(blocks[0])
    for i in range(0, 64, 8):
        row = "  ".join(f"W[{i+j:02d}]={W[i+j]:08X}" for j in range(8))
        print(f"    {COLOR_DIM}{row}{COLOR_RESET}")
    print(f"\n{COLOR_BOLD}  [ STEP 3 ] COMPRESSION — 64 ROUNDS{COLOR_RESET}")
    print(f"{COLOR_DIM}  Watching working variables (a..h) evolve each round.{COLOR_RESET}\n")
    h = list(_SHA256_H0)
    a, b, c, d, e, f, g, hh = h
    header = (
        f"  {'Rnd':>3}  "
        f"{'a':>10}  {'b':>10}  {'c':>10}  {'d':>10}  "
        f"{'e':>10}  {'f':>10}  {'g':>10}  {'h':>10}"
    )
    print(f"{COLOR_YELLOW}{header}{COLOR_RESET}")
    print(f"  {COLOR_DIM}{'─'*96}{COLOR_RESET}")
    init_row = (
        f"  {'  0':>3}  "
        f"{a:010X}  {b:010X}  {c:010X}  {d:010X}  "
        f"{e:010X}  {f:010X}  {g:010X}  {hh:010X}"
    )
    print(f"{COLOR_DIM}{init_row}{COLOR_RESET}")
    for i in range(64):
        S1 = _rotr32(e,6) ^ _rotr32(e,11) ^ _rotr32(e,25)
        ch = (e & f) ^ (~e & g) & 0xFFFFFFFF
        temp1 = (hh + S1 + ch + _SHA256_K[i] + W[i]) & 0xFFFFFFFF
        S0 = _rotr32(a,2) ^ _rotr32(a,13) ^ _rotr32(a,22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & 0xFFFFFFFF
        hh = g; g = f; f = e
        e = (d + temp1) & 0xFFFFFFFF
        d = c; c = b; b = a
        a = (temp1 + temp2) & 0xFFFFFFFF
        color = COLOR_GREEN if i % 8 == 7 else ""
        reset = COLOR_RESET if color else ""
        row = (
            f"  {i+1:>3}  "
            f"{a:010X}  {b:010X}  {c:010X}  {d:010X}  "
            f"{e:010X}  {f:010X}  {g:010X}  {hh:010X}"
        )
        print(f"{color}{row}{reset}")
        if delay > 0:
            time.sleep(delay)
    print(f"\n{COLOR_BOLD}  [ STEP 4 ] ADD COMPRESSED CHUNK TO HASH VALUES{COLOR_RESET}")
    final_h = [
        (h[0] + a)  & 0xFFFFFFFF,
        (h[1] + b)  & 0xFFFFFFFF,
        (h[2] + c)  & 0xFFFFFFFF,
        (h[3] + d)  & 0xFFFFFFFF,
        (h[4] + e)  & 0xFFFFFFFF,
        (h[5] + f)  & 0xFFFFFFFF,
        (h[6] + g)  & 0xFFFFFFFF,
        (h[7] + hh) & 0xFFFFFFFF,
    ]
    labels = ["H0","H1","H2","H3","H4","H5","H6","H7"]
    for label, val in zip(labels, final_h):
        print(f"    {COLOR_CYAN}{label}{COLOR_RESET} = {val:08X}")
    digest = "".join(f"{v:08X}" for v in final_h).lower()
    print(f"\n{COLOR_BOLD}  [ FINAL ] SHA-256 DIGEST{COLOR_RESET}")
    print(f"  {COLOR_GREEN}{digest}{COLOR_RESET}")
    expected = hashlib.sha256(message).hexdigest()
    if digest == expected:
        print(f"  {COLOR_DIM}✔ Verified correct against Python hashlib{COLOR_RESET}")
    else:
        print(f"  {COLOR_RED}✘ Mismatch with hashlib — check multi-block support{COLOR_RESET}")
    return digest
