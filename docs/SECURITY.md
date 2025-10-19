## SECURITY.md

# Security Methodology and Implementation

The `py_file_encrypt_tool` is designed with a **secure-by-default, auditable, and resilient** philosophy, leveraging modern, standard cryptographic primitives via Python's `cryptography` library (which wraps OpenSSL).

## 1. Cryptographic Primitives

The tool relies on the following industry-standard algorithms:

| Component | Algorithm | Purpose |
| :--- | :--- | :--- |
| **Symmetric Encryption** | **AES-256 GCM** (Galois/Counter Mode) | Provides strong **confidentiality** (only authorized users can read the data) and **authenticity/integrity** (detects any corruption or tampering). |
| **Key Derivation Function (KDF)** | **Argon2id** | Transforms the user's password into a strong 256-bit cryptographic key. Argon2id is the winner of the Password Hashing Competition and is memory-hard, resisting brute-force attacks via specialized hardware (GPUs/ASICs). |
| **Non-Cryptographic Checksum** | **SHA-256** | Used for user-level auditing and file identity verification *outside* the core crypto process. |

***

## 2. Secure Encryption Flow

The tool follows a robust, randomized, and authenticated encryption process for every file:

1.  **Unique Randomization:** A new, cryptographically secure 16-byte **Salt** and a 12-byte **Nonce** (Initialization Vector) are generated using `os.urandom()` for *every* encryption operation.
2.  **Key Derivation:** The user's password, the unique **Salt**, and the **Argon2id parameters** (memory, time, lanes) are fed into the Argon2id function to derive the 256-bit AES key.
3.  **Authentication Binding (AAD):** The entire file header—including the **File Version**, **KDF Parameters**, **Salt**, and **Nonce**—is passed as **Additional Authenticated Data (AAD)**. This cryptographically binds the metadata to the ciphertext, preventing an attacker from tampering with any part of the header without invalidating the GCM tag.
4.  **Streaming Encryption:** File contents are read in 64 KiB chunks and encrypted sequentially to maintain low memory usage (streaming).
5.  **Tag Generation:** Upon completion, the AES-256 GCM algorithm generates a 16-byte **Authentication Tag**, which is appended to the encrypted file.

***

## 3. Integrity and Operational Safety

The tool is built to prevent data loss or integrity issues from both malicious tampering and operational failures.

### A. GCM Tag Validation (Cryptographic Safety)

* The GCM Authentication Tag is the primary security check.
* If a decryption attempt fails the tag check (due to wrong password or tampering), the `cryptography.exceptions.InvalidTag` is raised.
* Upon `InvalidTag` failure, the tool immediately halts the process and **deletes the partially written plaintext file** to prevent leaking incomplete or unverified data.

### B. Atomic Decryption (Operational Safety)

* To guard against system failure (e.g., power loss, crash) during decryption, the tool employs a **write-to-temp-then-rename** strategy.
* The decrypted data is written to a temporary file (`.tmp`).
* The file is **only renamed** to the final output name after the GCM tag has been fully verified and the decryption process successfully completed. This ensures the user is only left with a **complete, verified plaintext file**.

### C. Checksum Verification (Auditing)

* The tool supports an optional decryption verification feature (`--verify-report-path`).
* This feature reads the **original SHA-256 hash** from the encryption report and compares it against the hash of the **newly decrypted file**.
* This process provides a final, user-facing audit to confirm that the decrypted file is bit-for-bit identical to the file that was originally encrypted.

***

## 4. Maintenance and Future-Proofing

The long-term security of the tool relies on the customizability of the KDF:

* **Parameter Persistence:** Argon2id resource costs (`memory_cost`, `iterations`, `lanes`) are permanently stored in the encrypted file header. This is a critical feature that ensures files can be decrypted regardless of what the application's current default settings are.
* **KDF Tuning:** As computer hardware improves, the default Argon2id parameters (currently `memory_cost=65536` KiB, `iterations=4`) **must be regularly benchmarked and increased** in the source code to maintain resistance against password brute-forcing.