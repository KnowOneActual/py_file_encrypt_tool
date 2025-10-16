***
⚠️ **Development Status: Under Active Development** ⚠️
This tool is currently in the early development phase and is **not stable**. Do not use it for sensitive or critical data until a stable, versioned release is announced. Use at your own risk.
***

# Python File Encrypt tool (py_file_encrypt_tool)

![Python](https://img.shields.io/badge/python-3.9+-blue?style=for-the-badge&logo=python)
![Crypto](https://img.shields.io/badge/Cryptography-OpenSSL-lightgrey?style=for-the-badge&logo=openssl)
![Status](https://img.shields.io/badge/Status-Alpha%20(Unstable)-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)

A simple, secure, and cross-platform command-line tool for encrypting sensitive data before storing it on a third-party cloud server.

The primary goal of this tool is to make file encryption easy, transparent, and secure-by-default, enforcing industry best practices while providing an accessible user experience.

## Features

### 1. Secure Defaults ("The Easy Button")
The tool uses a simple command to encrypt a file with zero configuration, automatically applying the strongest available settings:
* **Algorithm:** AES-256 in GCM (Galois/Counter Mode) for authenticated encryption.
* **Key Derivation:** Argon2id (or a modern, high-iteration PBKDF2) to convert your passphrase into a secure cryptographic key.
* **Output:** A single, securely packaged file containing the ciphertext, Initialization Vector (IV), and Authentication Tag.

### 2. Transparency and Reporting
Every encryption operation generates a detailed, human-readable report (e.g., JSON or text file) documenting *exactly* which algorithm, mode, and KDF parameters were used. This provides auditable proof of the security settings.

### 3. Flexible Control
For advanced users, the tool will include flags to manually select the encryption algorithm, key derivation function, and set parameters like KDF memory and iteration counts.

### 4. Cross-Platform
Developed in **Python**, the tool is designed for reliable use on:
* **macOS**
* **Linux**
* **Windows** (Planned support via standalone executables, possibly using PyInstaller for user convenience.)

## Getting Started (Planned)

### Installation
The tool requires Python 3.9 or later and the `cryptography` library.

```bash
# Clone the repository
git clone [https://github.com/KnowOneActual/py_file_encrypt_tool.git](https://github.com/py_file_encrypt_tool.git)
cd py_file_encrypt_tool

# Install dependencies
pip install -r requirements.txt
````

### Basic Usage (Encrypt)

To encrypt a file using the secure defaults:

```bash
python encrypt_app.py --encrypt my_sensitive_data.pdf
# The tool will prompt you for a passphrase.
# Output will be: my_sensitive_data.pdf.enc and my_sensitive_data.pdf.report.txt
```

### Basic Usage (Decrypt)

To decrypt a file:

```bash
python encrypt_app.py --decrypt my_sensitive_data.pdf.enc
# The tool will prompt you for the passphrase.
# Output will be: my_sensitive_data.pdf
```

## Next Steps

1.  Set up the basic file and project structure.
2.  Implement the core encryption/decryption logic using the Python `cryptography` library.
3.  Develop the `argparse` structure for the CLI.
4.  Implement the automatic security report generation.