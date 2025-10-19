
# Python File Encrypt CLI tool (py_file_encrypt_tool)

***
✨ **VERSION: 0.1.0-beta.1** ✨
✅ **Development Status: Core Functionality Stable (Beta)** ✅
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

## Getting Started

### Installation
The tool requires Python 3.9+ and the `cryptography` library. It is highly recommended to use a virtual environment.

```bash
# Clone the repository
git clone https://github.com/KnowOneActual/py_file_encrypt_tool.git
cd py_file_encrypt_tool
```

# Create and activate virtual environment
```bash
python3 -m venv venv
source venv/bin/activate  # macOS/Linux
```

# Install dependencies
```bash
pip install requirements.txt
```

### Basic Usage (Encrypt - The Easy Button)

Encrypts a file using all secure default settings. You will be prompted for a password (minimum 8 characters) and confirmation. 

```bash
python encrypt_app.py --encrypt my_sensitive_data.pdf
# Output: my_sensitive_data.pdf.enc and my_sensitive_data.pdf.report.json
```

### Basic Usage (Decrypt)

Decrypts the file. It will automatically read the KDF settings from the encrypted file header.

```bash
python encrypt_app.py --decrypt my_sensitive_data.pdf.enc
# Output: my_sensitive_data.pdf
```

### Advanced Usage (Decryption with Verification)

After successful decryption, use the `--verify-report-path` flag to automatically check the decrypted file's integrity against the original hash stored in the report.

```bash
python encrypt_app.py --decrypt my_sensitive_data.pdf.enc 
--verify-report-path my_sensitive_data.pdf.report.json
```
