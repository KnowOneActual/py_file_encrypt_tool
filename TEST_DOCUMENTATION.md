# Test Documentation for decrypt_file Function

## Overview
This document describes the unit tests created for the `decrypt_file` function, specifically focusing on the temporary file handling refactor that uses `tempfile.NamedTemporaryFile` for secure decryption.

## Test File
`test_decrypt_file.py` - Contains comprehensive unit tests for the `decrypt_file` function.

## Test Classes

### 1. TestDecryptFileTemporaryFileHandling
Tests that verify the secure handling of temporary files during decryption using `tempfile.NamedTemporaryFile`.

#### Test Cases:

##### test_tempfile_created_in_correct_directory
- **Purpose**: Verifies that `NamedTemporaryFile` is created in the output file's parent directory
- **What it tests**: 
  - The `dir` parameter passed to `NamedTemporaryFile` matches the output file's parent directory
  - The `delete=False` parameter is set (so we can control cleanup)
- **Why it matters**: Ensures temporary files are created in the correct location for atomic rename operations

##### test_tempfile_cleaned_up_on_user_abort
- **Purpose**: Verifies that temporary files are properly cleaned up when user aborts overwrite
- **What it tests**:
  - When user declines to overwrite an existing file, `os.remove` is called to clean up the temporary file
  - No temporary files are left behind after user abort
- **Why it matters**: Prevents disk space waste and ensures no sensitive data remains in temporary files

##### test_tempfile_cleaned_up_on_invalid_tag
- **Purpose**: Verifies that temporary files are properly cleaned up when decryption fails
- **What it tests**:
  - When decryption fails due to wrong password (InvalidTag exception), `os.remove` is called
  - No temporary files are left behind after decryption failure
  - The final output file is not created when authentication fails
- **Why it matters**: Ensures secure cleanup on authentication failure and prevents partial/corrupted files

##### test_tempfile_renamed_atomically_on_success
- **Purpose**: Verifies atomic rename operation on successful decryption
- **What it tests**:
  - `os.rename` is called to atomically move the temporary file to the final output location
  - The destination of the rename matches the expected output file
  - The final decrypted file exists and contains correct content
- **Why it matters**: Ensures atomic operations prevent race conditions and partial file writes

### 2. TestDecryptFileCorrectDecryption
Tests that verify the `decrypt_file` function correctly decrypts files after the temporary file handling refactor.

#### Test Cases:

##### test_decrypt_file_produces_correct_output
- **Purpose**: End-to-end test verifying correct decryption
- **What it tests**:
  - File encrypted with `encrypt_file` can be decrypted with `decrypt_file`
  - Decrypted content exactly matches original plaintext
- **Why it matters**: Validates the core functionality still works after refactoring

##### test_decrypt_file_with_large_content
- **Purpose**: Verifies streaming decryption works for large files
- **What it tests**:
  - Files larger than CHUNK_SIZE (64KB) are correctly decrypted
  - All bytes are preserved during streaming operations
- **Why it matters**: Ensures the chunked I/O implementation handles large files correctly

##### test_decrypt_file_fails_with_wrong_password
- **Purpose**: Verifies security - authentication failure prevents decryption
- **What it tests**:
  - Using wrong password prevents output file creation
  - GCM authentication tag verification works correctly
- **Why it matters**: Validates cryptographic authentication prevents unauthorized access

##### test_decrypt_file_no_temp_file_left_on_success
- **Purpose**: Verifies no temporary files remain after successful operation
- **What it tests**:
  - After successful decryption, no files starting with 'tmp' remain in directory
- **Why it matters**: Ensures clean operation without leaving artifacts

##### test_decrypt_file_preserves_binary_content
- **Purpose**: Verifies binary data integrity
- **What it tests**:
  - All 256 possible byte values are correctly preserved
  - Binary files (not just text) are handled correctly
- **Why it matters**: Ensures the implementation doesn't corrupt binary data

## Running the Tests

To run all tests:
```bash
python -m unittest test_decrypt_file -v
```

To run only temporary file handling tests:
```bash
python -m unittest test_decrypt_file.TestDecryptFileTemporaryFileHandling -v
```

To run only correct decryption tests:
```bash
python -m unittest test_decrypt_file.TestDecryptFileCorrectDecryption -v
```

To run a specific test:
```bash
python -m unittest test_decrypt_file.TestDecryptFileTemporaryFileHandling.test_tempfile_created_in_correct_directory -v
```

## Test Results

All 9 tests pass successfully, covering:
- ✅ Temporary file creation in correct directory
- ✅ Temporary file cleanup on user abort
- ✅ Temporary file cleanup on authentication failure
- ✅ Atomic rename on successful decryption
- ✅ Correct decryption output
- ✅ Large file handling
- ✅ Wrong password rejection
- ✅ No temporary file leaks
- ✅ Binary content preservation

## Implementation Details

The tests use a combination of:
- **Real file operations**: Integration tests that encrypt and decrypt actual files
- **Mock objects**: For controlling user input and monitoring system calls
- **Wrapped mocks**: Using `wraps` parameter to monitor calls while allowing real execution
- **Temporary directories**: Each test uses `tempfile.mkdtemp()` for isolation

## Key Security Validations

1. **Secure temporary file location**: Temporary files are created in the output directory, not in a shared temp location
2. **Atomic operations**: `os.rename` ensures no partial writes to final destination
3. **Cleanup on failure**: All error paths properly remove temporary files
4. **Authentication verification**: Wrong passwords prevent file creation
5. **No data leaks**: Temporary files don't persist after operations
