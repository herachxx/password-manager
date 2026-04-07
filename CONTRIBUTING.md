# Contributing

Contributions are welcome. This project has a strong emphasis on code clarity and security correctness — please read this guide before submitting a pull request.

## Ground Rules

- **No external libraries.** Every feature must be implementable with the Python standard library. This is a hard constraint, not a preference. If a feature genuinely requires a third-party library it belongs in a separate project.
- **No magic numbers.** All constants go in `constants.py` with a comment explaining their value and origin.
- **Every function gets a docstring.** Explain what it does, why it exists, and document any non-obvious security rationale.
- **Max ~40 lines per function.** If it's longer, it should probably be split.
- **Python 3.10+.** Type hints on all public function signatures.

## Setting Up

```bash
git clone https://github.com/yourusername/password-manager.git
cd password-manager
python main.py
python install.py --check
```

No virtual environment or package installation required.

## How to Contribute

### Reporting a bug

Open a GitHub issue with:
- Python version and OS
- Steps to reproduce
- What you expected vs what happened
- The relevant error message or traceback (redact any personal data)

For security vulnerabilities, follow the process in [SECURITY.md](SECURITY.md) instead of opening a public issue.

### Proposing a feature

Open an issue first to discuss it before writing code. This avoids wasted effort on features that don't fit the project's scope.

Features that are always welcome:
- Improvements to the SHA-256 visualizer
- Additional vault audit checks
- Vault export formats (encrypted)
- Improvements to the installer

Features that are out of scope:
- External library dependencies
- GUI features (those belong in Part 2)

### Submitting a pull request

1. Fork the repository and create a branch: `git checkout -b feature/your-feature-name`
2. Make your changes
3. Run the import check: `python install.py --check .`
4. Make sure `python main.py` still starts without errors
5. Update `CHANGELOG.md` under an `[Unreleased]` section
6. Open a PR with a clear description of what changed and why

## Code Style

- 4-space indentation
- `UPPER_SNAKE_CASE` for module-level constants
- `_leading_underscore` for internal/private functions
- Align assignment operators in blocks of related constants (see `constants.py`)
- Keep imports grouped: stdlib first, then local modules

## Cryptographic Changes

Any change to `crypto.py` or the vault format in `vault.py` requires:

1. A reference to the relevant standard (FIPS, RFC, NIST SP)
2. A clear explanation of the security rationale in the docstring
3. Verification that the output still matches the reference implementation (for `visualize_sha256`, the output must match `hashlib.sha256`)
4. A note in `CHANGELOG.md` and `SECURITY.md` if the change affects the threat model

**The vault file format is considered stable.** Breaking changes to the format require a version bump in `VAULT_VERSION` and a migration path for existing vaults.
