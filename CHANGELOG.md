# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-beta.1] - 2025-10-19 

### Added
- **Core Cryptography:** Implemented secure, authenticated encryption using **AES-256 GCM** and **Argon2id** Key Derivation.
- **Security Report:** Added a feature to generate a detailed JSON report (with KDF settings, salt, and nonce) for transparency and auditing.
- **Passphrase Security:** Implemented verified password entry and enforced a minimum length of 8 characters.
- **Non-Cryptographic Integrity Check:** Automatically calculates the **SHA-256 checksum** of the original file during encryption and includes it in the report.
- **Optional Verification:** Added the `--verify-report-path` flag to automatically verify the decrypted file's hash against the original hash stored in the report.
- **Decryption Resilience:** Implemented **Atomic Decryption (write-to-temp-then-rename)** to prevent file corruption in case of system failure during the decryption process.
- **Insecure Override (`--force-insecure-decrypt`):** Included for security demonstration, this highly-warned flag allows bypassing the GCM integrity check to save corrupted data, with the resulting file clearly renamed using the `.unverified_corrupt` suffix.

### Changed
- **Large File Support (Streaming):** Refactored both encryption and decryption to use file streaming, enabling low-memory processing of files of arbitrary size.
- **Cross-Platform KDF Persistence:** Modified the encrypted file format to embed all Argon2id parameters (memory cost, iterations, lanes) in the header, guaranteeing successful decryption of files encrypted with custom settings on any machine.
- **Robust Path Handling:** Refactored file path logic using `pathlib.Path.resolve()` to ensure files are correctly located and written regardless of the user's current working directory.
- **Critical Security Enhancement:** Expanded the **GCM Additional Authenticated Data (AAD)** to include the entire file header (KDF parameters, Salt, and Nonce), cryptographically preventing tampering with any piece of metadata.

### Fixed
- Resolved `ModuleNotFoundError` by clarifying environment setup requirements.
- Corrected Python `SyntaxError` related to misplaced keywords.
- Fixed `Argon2id` keyword argument errors (`t_cost`, `length`) to align with the `cryptography` library API.
- Replaced deprecated `datetime.utcnow()` with the timezone-aware `datetime.now(datetime.UTC)` to ensure correct timestamping in reports.