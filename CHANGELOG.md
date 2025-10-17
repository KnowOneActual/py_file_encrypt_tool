# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project setup.
- **Core Encryption/Decryption Logic:** Implemented secure, authenticated encryption using **AES-256 GCM** and **Argon2id** Key Derivation.
- **Cross-Platform Compatibility:** Designed a custom file format to ensure successful decryption across different operating systems (macOS/Linux/Windows).
- **Security Report:** Added a feature to generate a JSON report detailing the exact KDF parameters, salt, and nonce for transparency and auditing.
- **Passphrase Security:** Implemented verified password entry and enforced a minimum length of 8 characters.

### Changed
- **KDF Parameter Persistence:** Modified the encrypted file format to embed Argon2id parameters (memory, iterations, lanes) in the header using `struct`, enabling files encrypted with custom settings to be decrypted correctly anywhere (Full Manual Mode).
- **File Path Handling:** Refactored path logic using `pathlib.Path.resolve()` to ensure robust file access regardless of the current working directory.
- **Large File Support (Streaming):** Implemented file streaming for both encryption and decryption to handle files of arbitrary size efficiently without consuming excessive memory.

### Fixed
- Resolved `SyntaxError` due to misplaced import statement.
- Corrected `Argon2id` keyword argument errors (`t_cost`, `length`) to align with the `cryptography` library API.
- Replaced deprecated `datetime.utcnow()` with `datetime.now(datetime.UTC)` to ensure correct timestamping and eliminate warnings.