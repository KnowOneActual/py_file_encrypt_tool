## Test Plan

### 1. Functional & Security Tests (Core Crypto Logic)

These tests ensure the encryption process is correct, secure, and fails gracefully when integrity is compromised.

| Test ID | Scenario | Expected Outcome |
| :--- | :--- | :--- |
| **F-1.1** | **Standard Round Trip:** Encrypt a small text file using the default settings ("Easy Button") and immediately decrypt it. | Decryption **SUCCESS**. The decrypted file is **bit-for-bit identical** to the original (confirmed by a manual SHA-256 hash or simple comparison). |
| **F-1.2** | **Wrong Password (GCM Fail):** Attempt to decrypt a file using the wrong password. | Decryption **FAILURE** with an "Incorrect password or the file has been tampered with" error. No plaintext file is created. |
| **F-1.3** | **Tampering (GCM Fail):** Encrypt a file. Use a hex editor or simple command (e.g., `echo 'corrupt' >> file.enc`) to alter a single byte in the ciphertext portion of the `.enc` file. Attempt decryption. | Decryption **FAILURE** with the `InvalidTag` error. The partially decrypted **`.tmp` file is deleted** (validating the atomic rename/cleanup). |
| **F-1.4** | **Header Tampering (AAD Fail):** Encrypt a file. Alter a single byte in the **KDF Parameters, Salt, or Nonce** section of the `.enc` file. Attempt decryption. | Decryption **FAILURE** with the `InvalidTag` error. The partially decrypted **`.tmp` file is deleted** (validating the Expanded AAD security fix). |
| **F-1.5** | **Password Min-Length:** Attempt encryption using a password of only 7 characters. | Encryption **FAILURE** with a clear error message requiring the minimum 8 characters. |

***

### 2. Robustness & Integrity Tests

These tests specifically target the streaming and checksum features for large file handling and advanced verification.

| Test ID | Scenario | Expected Outcome |
| :--- | :--- | :--- |
| **R-2.1** | **Large File Streaming:** Encrypt a file larger than 100MB (significantly larger than `CHUNK_SIZE`). | Encryption **SUCCESS**. Memory usage remains low during the process (confirming streaming). |
| **R-2.2** | **Custom KDF Parameters:** Encrypt a file using custom flags (e.g., `--kdf-time 8 --kdf-memory 131072`). Decrypt the file *without* specifying any custom flags. | Decryption **SUCCESS**. The decryption tool must successfully read the KDF parameters from the file header and derive the correct key. |
| **R-2.3** | **Decryption Checksum Success:** Encrypt a file. Immediately decrypt it using the verification flag (`--decrypt file.enc --verify-report-path report.json`). | Decryption **SUCCESS**. The output includes the message: "✅ VERIFICATION SUCCESS". |
| **R-2.4** | **Decryption Checksum Failure:** Encrypt a file and generate the report. Decrypt the file. Manually alter the decrypted file. Recalculate the checksum of the modified file and compare it against the report's hash. | **(Manual Check)** The hashes should **NOT match**. The automated verification should show: "❌ VERIFICATION FAILURE". |
| **R-2.5** | **Atomic Rename:** Encrypt a large file. During decryption, manually terminate the process (e.g., `Ctrl+C`) when the progress is halfway. | Decryption **ABORTS**. No final output file is created. Only a temporary `.tmp` file (if one was created) is cleaned up or left with the `.tmp` suffix, ensuring the final filename is never corrupted. |

***

### 3. Usability & Cross-Platform Tests

These validate the CLI, output, and multi-OS usage.

| Test ID | Scenario | Expected Outcome |
| :--- | :--- | :--- |
| **U-3.1** | **Cross-Platform Decrypt:** Encrypt a file on **macOS** (or your current environment). Transfer the encrypted file (`.enc`) and the report (`.report.json`) to a **Linux** machine. Decrypt the file on the Linux machine using the same password. | Decryption **SUCCESS**. The file is recovered and verifiable. |
| **U-3.2** | **Relative Path Handling:** Run the `encrypt_app.py` script from a directory *outside* the project folder, using a relative path to the input file (e.g., `python /path/to/encrypt_app.py --encrypt ../data/file.txt`). | Encryption **SUCCESS**. The script correctly resolves the input path and performs the operation (validating the `.resolve()` fix). |
| **U-3.3** | **Output Naming Defaults:** Encrypt a file without using the `-o` or `--output` flag. | Encryption **SUCCESS**. The output file is correctly named with the default suffix (e.g., `file.txt.enc`). |
| **U-3.4** | **Help Message:** Run the script with `-h` or `--help`. | A clean, readable help message is displayed, correctly listing the "Custom KDF Settings" and the `--verify-report-path` advanced option. |