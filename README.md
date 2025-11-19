<p align="center">
<img src="assets/img/py_file_encrypt_tool_logo.webp" alt="alt text" width="150">
</p>


# Python File Encrypt CLI Tool (py_file_encrypt_tool)

***
✨ **VERSION: 0.1.0-beta.2** ✨
✅ **Development Status: Core Functionality Stable (Beta)** ✅
The core encryption, decryption, and streaming pipeline is stable and ready for testing.
***

![Python](https://img.shields.io/badge/python-3.9+-blue?style=for-the-badge&logo=python)
![Crypto](https://img.shields.io/badge/Cryptography-OpenSSL-lightgrey?style=for-the-badge&logo=openssl)
![Status](https://img.shields.io/badge/Status-Beta-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)
A simple, secure, and **cross-platform** command-line tool for encrypting sensitive data before storing it on a third-party cloud server.

The primary goal of this tool is to make file encryption easy, transparent, and **secure-by-default**, enforcing industry best practices while remaining highly efficient for large data sets.

## Core Security and Features

### 1. Secure Defaults ("The Easy Button")
The tool uses a simple command to encrypt a file with zero configuration, automatically applying the strongest available settings:
* **Algorithm:** AES-256 in GCM (Galois/Counter Mode) for authenticated encryption.
* **Key Derivation:** Argon2id, the winner of the Password Hashing Competition, is used to convert your passphrase into a secure cryptographic key.
* **Password Generation:** The new `--generate-password` flag creates a secure 18-character (default) password and saves it directly to the JSON report file.

### 2. Integrity and Resilience
* **Atomic Decryption (Operational Safety):** Decryption uses a **write-to-temp-then-rename** strategy. The final output file is only written after the cryptographic integrity check passes, preventing system crashes from leaving behind corrupted, unverified data.
* **Header Authentication (AAD):** The entire file header (KDF parameters, salt, and nonce) is included in the GCM's **Additional Authenticated Data (AAD)** to cryptographically prevent tampering with any decryption settings.
* **Large File Streaming:** Both operations are implemented with file streaming, ensuring low memory usage and high performance for files of arbitrary size.
* **Cross-Platform Persistence:** Argon2id parameters are automatically embedded in the encrypted file header, guaranteeing that files encrypted with custom settings can be decrypted correctly on any OS.

### 3. Auditing and Verification
* **Automatic Checksum:** The tool automatically calculates the **SHA-256 hash** of the original file before encryption and includes it in the final report for auditability.
* **Verification Mode:** Decryption supports the `--verify-report-path` flag to automatically check the decrypted file's integrity against the original hash recorded in the report.

## Getting Started

### Installation
The tool requires Python 3.9+ and the `cryptography` library. It is highly recommended to use a virtual environment.

```bash
# Clone the repository
git clone [https://github.com/KnowOneActual/py_file_encrypt_tool.git](https://github.com/KnowOneActual/py_file_encrypt_tool.git)
cd py_file_encrypt_tool

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # macOS/Linux

# Install dependencies
pip install requirements.txt
````

### Basic Usage Examples (The "Easy Button" and Common Flows)

**1. Encrypt a file (The Easy Button)**

```bash
python encrypt_app.py --encrypt "my_sensitive_data.pdf"
# Output: my_sensitive_data.pdf.enc and my_sensitive_data.pdf.report.json
```

**2. Decrypt a file**

```bash
python encrypt_app.py --decrypt "my_sensitive_data.pdf.enc"
# Output: my_sensitive_data.pdf
```

**3. Decrypt and verify integrity against the original report**

```bash
python encrypt_app.py --decrypt "file.enc" --verify-report-path "file.report.json"
```

**4. Encrypt using a generated password (WARNING: Password saved in .report.json)**

```bash
python encrypt_app.py --encrypt "file.txt" --generate-password
```

**5. Encrypt using a generated password of a specific length (10-20)**

```bash
python encrypt_app.py --encrypt "file.txt" --generate-password 20
```