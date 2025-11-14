
# Python File Encrypt CLI tool (py_file_encrypt_tool)

***
✨ **VERSION: 0.1.0-beta.3** ✨
✅ **Development Status: Quality of Life & Safety Update (Beta)** ✅
The core encryption, decryption, and streaming pipeline is stable and ready for testing.
***

![Python](https://img.shields.io/badge/python-3.9+-blue?style=for-the-badge&logo=python)
![Crypto](https://img.shields.io/badge/Cryptography-OpenSSL-lightgrey?style=for-the-badge&logo=openssl)
![Status](https://img.shields.io/badge/Status-Beta-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)

A simple, secure, and **cross-platform** command-line tool for encrypting sensitive data before storing it on a third-party cloud server.

The primary goal of this tool is to make file encryption easy, transparent, and **secure-by-default**, enforcing industry best practices while remaining highly efficient for large data sets.

## Features

### 1. Secure Defaults ("The Easy Button")

The tool uses a simple command to encrypt a file with zero configuration, automatically applying the strongest available settings:

  * **Algorithm:** AES-256 in GCM (Galois/Counter Mode) for authenticated encryption.
  * **Key Derivation:** Argon2id to convert your passphrase into a secure cryptographic key.

### 2. Robustness and Cross-Platform Guarantees

  * **Large File Streaming:** Both encryption and decryption operations are implemented using file streaming, ensuring low memory usage and high performance, regardless of file size.
  * **Cross-Platform KDF Persistence:** Argon2id parameters (memory cost, time cost, parallelism) are automatically embedded in the encrypted file header, guaranteeing that files encrypted with custom settings can be decrypted correctly on any OS (macOS, Linux, Windows).

### 3. Transparency and Verification

  * **Automatic Checksum:** The tool automatically calculates the **SHA-256 hash** of the original file before encryption and includes it in the final report.
  * **Auditable Report:** Every encryption operation generates a detailed JSON report documenting the algorithm, KDF parameters, salt, and original file hash for auditability.
  * **Verification:** Decryption supports an optional verification mode to automatically compare the decrypted file's hash against the hash recorded in the original report.

### 4. Quality of Life & Safety

  * **Shorthand Flags:** Common commands have simple shorthands (`-e`, `-d`, `-o`, `-v`, `-g`).
  * **Password Generation:** A built-in password generator (`-g`) can be used for non-interactive encryption.
  * **Overwrite Protection:** The tool prevents accidental data loss by prompting the user before overwriting any existing files.
  * **Smart Verification:** The decrypt command automatically finds its corresponding `.report.json` file and asks the user if they want to run a verification.
  * **Scripting Support:** A `--password-stdin` flag allows the password to be piped in, enabling use in automated scripts.

-----

## Installation

The tool requires Python 3.9+ and the `cryptography` library. It is highly recommended to use a virtual environment.

```bash
# Clone the repository
git clone https://github.com/KnowOneActual/py_file_encrypt_tool.git
cd py_file_encrypt_tool
```

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # macOS/Linux
```

```bash
# Install dependencies
pip install requirements.txt
```

-----

## Basic Usage

### Encrypt & Decrypt (with "Smart" Verification)

Use `-e` to encrypt. You will be prompted for a password (minimum 8 characters) and confirmation.

```bash
python encrypt_app.py -e my_sensitive_data.pdf
# Output: my_sensitive_data.pdf.enc and my_sensitive_data.pdf.report.json
```

Use `-d` to decrypt. You will be prompted for the password.

```bash
python encrypt_app.py -d my_sensitive_data.pdf.enc
# Output:
# Found report: my_sensitive_data.pdf.report.json
# Verify decrypted file against this report? (Y/n) y
# ...
# ✅ VERIFICATION SUCCESS
# Output: my_sensitive_data.pdf
```

### Usage (Password Generation)

Use `-g` to generate a secure password automatically. This is ideal for scripts, but **you must secure the report file.**

```bash
python encrypt_app.py -e "secret_archive.zip" -g
# Output:
# Generating new 18-character password...
# ...
# ⚠️ ⚠️  PASSWORD GENERATED AND SAVED IN REPORT ⚠️ ⚠️
# It has been saved in the JSON report: secret_archive.zip.report.json
# WARNING: This is your ONLY copy. Secure this report file.
```

### Advanced Usage (Scripting with stdin)

For use in automated scripts, you can pipe a password to `stdin`.

```bash
echo "MySuperSecretP@ssword" | python encrypt_app.py -e "file.txt" --password-stdin
```

-----

## Testing & Robustness

This tool is tested against a comprehensive plan to ensure cryptographic integrity, data safety, and usability.

### Core Crypto & Security

  * Standard round-trip (encrypt/decrypt) success.
  * Decryption **failure** with wrong password.
  * Decryption **failure** from ciphertext tampering (GCM tag fail).
  * Decryption **failure** from header tampering (KDF/Salt/Nonce AAD fail).
  * Enforces minimum 8-character password.

### Robustness & Data Integrity

  * Streaming I/O for large files (low memory) is confirmed.
  * Overwrite protection for existing files.
  * SHA-256 integrity verification (manual and smart-prompted).
  * Atomic decryption (no corrupt files are written on failure).
  * Custom KDF parameters are successfully read from the header.

### Usability & Platform

  * Cross-platform decryption (macOS/Linux) is verified.
  * Shorthand flags, help messages, and error messages are clear.
  * Scripting support via `stdin` functions as expected.

For the complete test matrix, see [docs/test\_plan\_outline.md](https://www.google.com/search?q=docs/test_plan_outline.md).