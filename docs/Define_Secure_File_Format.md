# Define Secure File Format

To ensure cross-platform compatibility and transparent decryption, it is crucial to define a consistent, structured way to store the data in the encrypted file (.enc).

A secure encrypted file should contain the following four main components, stored in this order:

### 1. Header/Metadata

Specifies the KDF and encryption settings needed for decryption.

| Field | Purpose | Size (Bytes) | Notes |
| --- | --- | --- | --- |
| KDF Name | specifies the KDF algorithm used | variable | e.g., Argon2id |
| Salt | random bytes used to make the KDF unique | 16 | crucial for security |
| Iterations | specifies the number of iterations for the KDF | variable | e.g., 4 |
| Memory Cost | specifies the memory cost for the KDF | variable | e.g., 65536 |

### 2. Salt

random bytes used to make the Key Derivation Function unique.

| Field | Purpose | Size (Bytes) | Notes |
| --- | --- | --- | --- |
| Salt | random bytes used to make the KDF unique | 16 | crucial for security |

### 3. IV (Initialization Vector) or Nonce

random bytes used to start the encryption process.

| Field | Purpose | Size (Bytes) | Notes |
| --- | --- | --- | --- |
| IV/Nonce | random bytes used to start the encryption process | 12 | must be unique for every single encryption operation |

### 4. Ciphertext

the actual encrypted content of the original file.

| Field | Purpose | Size (Bytes) | Notes |
| --- | --- | --- | --- |
| Ciphertext | the actual encrypted content of the original file | variable | - |

### 5. Authentication Tag

a cryptographic checksum to verify integrity and authenticity.

| Field | Purpose | Size (Bytes) | Notes |
| --- | --- | --- | --- |
| Authentication Tag | a cryptographic checksum to verify integrity and authenticity | 16 | used to detect tampering during decryption |
