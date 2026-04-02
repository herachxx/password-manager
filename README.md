# password-manager

## What is hashing and why do we need it?

A hash function takes any input (a string, a file, anything) and produces a fixed-length "fingerprint". For SHA-256, the output is always 256 bits (64 hex characters).
Three critical properties:
- One-way - you cannot reverse a hash back to the original input
- Deterministic - same input always gives the same output
- Avalanche effect - changing one character completely changes the output

This is why we never store raw passwords. We store their hash. When the user logs in, we hash what they typed and compare hashes.

## How SHA-256 works (the intuition)

SHA-256 processes your message in 512-bit chunks through 64 rounds of bit-mixing operations. It uses addition, XOR, bit-shifts and rotations - all integer math. No multiplication, no division.

