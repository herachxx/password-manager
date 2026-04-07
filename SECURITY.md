# Security Policy

## Scope

This project is an **educational implementation** of a password manager. It demonstrates applied cryptography concepts using only the Python standard library. The cryptographic primitives (AES-256, SHA-256, PBKDF2) are implemented from scratch for transparency and learning purposes.

**This software is not intended for production use** as the primary store of credentials for critical systems. For production use cases, consider a library-backed implementation using audited code such as `cryptography` (PyCA).

## What This Project Demonstrates

| Primitive | Implementation | Standard |
|---|---|---|
| AES-256-CBC | From scratch | FIPS 197 |
| PBKDF2-SHA256 | `hashlib.pbkdf2_hmac` | RFC 2898 |
| HMAC-SHA256 | `hmac` stdlib | RFC 2104 |
| PKCS#7 padding | From scratch | RFC 5652 |
| CSPRNG | `os.urandom` | OS-provided |

## Known Limitations

- **Not side-channel hardened.** Python integer operations are not guaranteed constant-time at the CPU level. The use of `hmac.compare_digest` mitigates timing attacks on MAC verification, but the AES implementation itself is not hardened against cache-timing attacks.
- **Single-device only.** No network communication occurs. This eliminates an entire class of remote attack surface, but also means no synchronisation.
- **Memory zeroing is best-effort.** The session key is explicitly zeroed via `bytearray` overwrite, but Python's memory allocator and the OS may retain copies in swap or memory pages before they are zeroed.

## Reporting a Vulnerability

If you discover a security issue in this project:

1. **Do not open a public GitHub issue.**
2. Email a description of the vulnerability, steps to reproduce, and potential impact.
3. You will receive a response within 72 hours acknowledging receipt.
4. Once confirmed, a fix will be prepared and the issue will be disclosed publicly with credit to the reporter.

Please include:
- A clear description of the vulnerability
- The affected file(s) and line numbers
- A proof-of-concept or reproduction steps
- Your assessment of severity and impact

## Security Design References

- NIST SP 800-132 - Recommendation for Password-Based Key Derivation
- FIPS 197 - Advanced Encryption Standard (AES)
- FIPS 180-4 - Secure Hash Standard (SHS)
- RFC 2898 - PKCS #5: Password-Based Cryptography Specification
- RFC 2104 - HMAC: Keyed-Hashing for Message Authentication
