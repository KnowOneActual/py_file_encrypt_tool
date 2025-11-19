import unittest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, mock_open, MagicMock, call
import struct

# Import the module to test
import encrypt_app
from encrypt_app import (
    decrypt_file, 
    encrypt_file,
    FILE_VERSION_HEADER,
    KDF_HEADER_FORMAT,
    KDF_HEADER_SIZE,
    ARGON2_SALT_LENGTH,
    GCM_NONCE_LENGTH,
    GCM_TAG_SIZE,
    CHUNK_SIZE,
    ENCRYPTED_FILE_SUFFIX,
    CORRUPTION_SUFFIX,
    KDF_SETTINGS
)


class TestDecryptFileTemporaryFileHandling(unittest.TestCase):
    """Test case 1: Verify that decrypt_file securely handles temporary files during decryption."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.test_plaintext_file = Path(self.test_dir) / "test_plaintext.txt"
        self.test_encrypted_file = Path(self.test_dir) / f"test_plaintext{ENCRYPTED_FILE_SUFFIX}"
        self.test_decrypted_file = Path(self.test_dir) / "test_decrypted.txt"
        self.test_password = "TestPassword123"
        self.test_content = b"Test content for temporary file handling."
        
        # Create test plaintext file
        with open(self.test_plaintext_file, 'wb') as f:
            f.write(self.test_content)
        
    def tearDown(self):
        """Clean up test files."""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    @patch('encrypt_app.get_verified_password')
    @patch('builtins.print')
    @patch('tempfile.NamedTemporaryFile', wraps=tempfile.NamedTemporaryFile)
    @patch('encrypt_app.input', return_value='y')
    def test_tempfile_created_in_correct_directory(self, mock_input, mock_named_temp, mock_print, mock_get_password):
        """Test that NamedTemporaryFile is created in the output file's parent directory."""
        # Mock password input
        mock_get_password.return_value = self.test_password
        
        # First, encrypt the file
        encrypt_file(
            input_file=self.test_plaintext_file,
            output_file=self.test_encrypted_file,
            password=self.test_password,
            settings=KDF_SETTINGS,
            password_was_generated=False
        )
        
        # Now decrypt the file
        decrypt_file(
            input_file=self.test_encrypted_file,
            output_file=self.test_decrypted_file,
            verify_report_path=None,
            password=self.test_password,
            force_insecure=False
        )
        
        # Verify that NamedTemporaryFile was called with the correct directory
        mock_named_temp.assert_called()
        call_kwargs = mock_named_temp.call_args[1]
        self.assertEqual(call_kwargs['dir'], self.test_decrypted_file.parent)
        self.assertEqual(call_kwargs['delete'], False)
    
    @patch('encrypt_app.get_verified_password')
    @patch('builtins.print')
    @patch('os.remove', wraps=os.remove)
    @patch('encrypt_app.input')
    def test_tempfile_cleaned_up_on_user_abort(self, mock_input, mock_remove, mock_print, mock_get_password):
        """Test that temporary file is cleaned up when user aborts overwrite."""
        # Mock password input
        mock_get_password.return_value = self.test_password
        
        # First, encrypt the file
        mock_input.return_value = 'y'  # Allow encryption
        encrypt_file(
            input_file=self.test_plaintext_file,
            output_file=self.test_encrypted_file,
            password=self.test_password,
            settings=KDF_SETTINGS,
            password_was_generated=False
        )
        
        # Create the output file to trigger overwrite prompt
        with open(self.test_decrypted_file, 'w') as f:
            f.write("existing file")
        
        # User says 'n' to overwrite during decryption
        mock_input.return_value = 'n'
        
        # Capture files before decryption attempt
        files_before = set(os.listdir(self.test_dir))
        
        # Attempt to decrypt - should abort
        decrypt_file(
            input_file=self.test_encrypted_file,
            output_file=self.test_decrypted_file,
            verify_report_path=None,
            password=self.test_password,
            force_insecure=False
        )
        
        # Verify that os.remove was called (temporary file cleanup)
        self.assertTrue(mock_remove.called, "os.remove should be called to clean up temp file")
        
        # Verify no new temp files left behind
        files_after = set(os.listdir(self.test_dir))
        temp_files = [f for f in files_after if f.startswith('tmp')]
        self.assertEqual(len(temp_files), 0, "No temp files should remain after user abort")
    
    @patch('encrypt_app.get_verified_password')
    @patch('builtins.print')
    @patch('os.remove', wraps=os.remove)
    @patch('encrypt_app.input', return_value='y')
    def test_tempfile_cleaned_up_on_invalid_tag(self, mock_input, mock_remove, mock_print, mock_get_password):
        """Test that temporary file is cleaned up when decryption fails due to InvalidTag."""
        # Mock password input
        mock_get_password.return_value = self.test_password
        
        # First, encrypt the file with correct password
        encrypt_file(
            input_file=self.test_plaintext_file,
            output_file=self.test_encrypted_file,
            password=self.test_password,
            settings=KDF_SETTINGS,
            password_was_generated=False
        )
        
        # Try to decrypt with wrong password (will cause InvalidTag)
        wrong_password = "WrongPassword456"
        
        # Attempt to decrypt with wrong password
        decrypt_file(
            input_file=self.test_encrypted_file,
            output_file=self.test_decrypted_file,
            verify_report_path=None,
            password=wrong_password,
            force_insecure=False
        )
        
        # Verify that os.remove was called on the temporary file
        self.assertTrue(mock_remove.called, "os.remove should be called to clean up temp file on failure")
        
        # Verify decrypted file was NOT created
        self.assertFalse(self.test_decrypted_file.exists(),
                        "Decrypted file should not exist when using wrong password")
        
        # Verify no temp files left behind
        files = os.listdir(self.test_dir)
        temp_files = [f for f in files if f.startswith('tmp')]
        self.assertEqual(len(temp_files), 0, "No temp files should remain after failed decryption")
    
    @patch('encrypt_app.get_verified_password')
    @patch('builtins.print')
    @patch('os.rename', wraps=os.rename)
    @patch('encrypt_app.input', return_value='y')
    def test_tempfile_renamed_atomically_on_success(self, mock_input, mock_rename, mock_print, mock_get_password):
        """Test that temporary file is atomically renamed to output file on successful decryption."""
        # Mock password input
        mock_get_password.return_value = self.test_password
        
        # First, encrypt the file
        encrypt_file(
            input_file=self.test_plaintext_file,
            output_file=self.test_encrypted_file,
            password=self.test_password,
            settings=KDF_SETTINGS,
            password_was_generated=False
        )
        
        # Now decrypt the file
        decrypt_file(
            input_file=self.test_encrypted_file,
            output_file=self.test_decrypted_file,
            verify_report_path=None,
            password=self.test_password,
            force_insecure=False
        )
        
        # Verify that os.rename was called to atomically move temp file to output
        self.assertTrue(mock_rename.called, "os.rename should be called for atomic file move")
        # Check that the last call was to rename something to our output file
        last_call_args = mock_rename.call_args[0]
        self.assertEqual(last_call_args[1], self.test_decrypted_file,
                        "os.rename should move temp file to final output location")
        
        # Verify the decrypted file exists and has correct content
        self.assertTrue(self.test_decrypted_file.exists(), "Decrypted file should exist")
        with open(self.test_decrypted_file, 'rb') as f:
            decrypted_content = f.read()
        self.assertEqual(decrypted_content, self.test_content,
                        "Decrypted content should match original")


class TestDecryptFileCorrectDecryption(unittest.TestCase):
    """Test case 2: Verify that decrypt_file correctly decrypts a file after the temporary file handling refactor."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.test_plaintext_file = Path(self.test_dir) / "test_plaintext.txt"
        self.test_encrypted_file = Path(self.test_dir) / f"test_plaintext{ENCRYPTED_FILE_SUFFIX}"
        self.test_decrypted_file = Path(self.test_dir) / "test_decrypted.txt"
        self.test_password = "SecureTestPassword123"
        self.test_content = b"This is a test file with some content for encryption and decryption testing."
        
        # Create test plaintext file
        with open(self.test_plaintext_file, 'wb') as f:
            f.write(self.test_content)
    
    def tearDown(self):
        """Clean up test files."""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    @patch('encrypt_app.input', return_value='y')
    @patch('encrypt_app.get_verified_password')
    @patch('builtins.print')
    def test_decrypt_file_produces_correct_output(self, mock_print, mock_get_password, mock_input):
        """Test that decrypt_file correctly decrypts a file encrypted by encrypt_file."""
        # Mock password input
        mock_get_password.return_value = self.test_password
        
        # First, encrypt the file
        encrypt_file(
            input_file=self.test_plaintext_file,
            output_file=self.test_encrypted_file,
            password=self.test_password,
            settings=KDF_SETTINGS,
            password_was_generated=False
        )
        
        # Verify encrypted file was created
        self.assertTrue(self.test_encrypted_file.exists(), "Encrypted file should exist")
        
        # Now decrypt the file
        decrypt_file(
            input_file=self.test_encrypted_file,
            output_file=self.test_decrypted_file,
            verify_report_path=None,
            password=self.test_password,
            force_insecure=False
        )
        
        # Verify decrypted file was created
        self.assertTrue(self.test_decrypted_file.exists(), "Decrypted file should exist")
        
        # Verify content matches original
        with open(self.test_decrypted_file, 'rb') as f:
            decrypted_content = f.read()
        
        self.assertEqual(decrypted_content, self.test_content, 
                        "Decrypted content should match original plaintext")
    
    @patch('encrypt_app.input', return_value='y')
    @patch('encrypt_app.get_verified_password')
    @patch('builtins.print')
    def test_decrypt_file_with_large_content(self, mock_print, mock_get_password, mock_input):
        """Test that decrypt_file correctly handles files larger than CHUNK_SIZE."""
        # Mock password input
        mock_get_password.return_value = self.test_password
        
        # Create large test content (larger than CHUNK_SIZE)
        large_content = b"A" * (CHUNK_SIZE * 2 + 1000)
        
        large_file = Path(self.test_dir) / "large_test.txt"
        with open(large_file, 'wb') as f:
            f.write(large_content)
        
        large_encrypted = Path(self.test_dir) / f"large_test{ENCRYPTED_FILE_SUFFIX}"
        large_decrypted = Path(self.test_dir) / "large_decrypted.txt"
        
        # Encrypt the large file
        encrypt_file(
            input_file=large_file,
            output_file=large_encrypted,
            password=self.test_password,
            settings=KDF_SETTINGS,
            password_was_generated=False
        )
        
        # Decrypt the large file
        decrypt_file(
            input_file=large_encrypted,
            output_file=large_decrypted,
            verify_report_path=None,
            password=self.test_password,
            force_insecure=False
        )
        
        # Verify content matches
        with open(large_decrypted, 'rb') as f:
            decrypted_content = f.read()
        
        self.assertEqual(decrypted_content, large_content,
                        "Decrypted large file content should match original")
        self.assertEqual(len(decrypted_content), len(large_content),
                        "Decrypted file size should match original")
    
    @patch('encrypt_app.input', return_value='y')
    @patch('encrypt_app.get_verified_password')
    @patch('builtins.print')
    def test_decrypt_file_fails_with_wrong_password(self, mock_print, mock_get_password, mock_input):
        """Test that decrypt_file fails gracefully with incorrect password."""
        # Mock password input for encryption
        mock_get_password.return_value = self.test_password
        
        # Encrypt the file
        encrypt_file(
            input_file=self.test_plaintext_file,
            output_file=self.test_encrypted_file,
            password=self.test_password,
            settings=KDF_SETTINGS,
            password_was_generated=False
        )
        
        # Try to decrypt with wrong password
        wrong_password = "WrongPassword456"
        decrypt_file(
            input_file=self.test_encrypted_file,
            output_file=self.test_decrypted_file,
            verify_report_path=None,
            password=wrong_password,
            force_insecure=False
        )
        
        # Verify decrypted file was NOT created (due to failed authentication)
        self.assertFalse(self.test_decrypted_file.exists(),
                        "Decrypted file should not exist when using wrong password")
    
    @patch('encrypt_app.input', return_value='y')
    @patch('encrypt_app.get_verified_password')
    @patch('builtins.print')
    def test_decrypt_file_no_temp_file_left_on_success(self, mock_print, mock_get_password, mock_input):
        """Test that no temporary files are left in the directory after successful decryption."""
        # Mock password input
        mock_get_password.return_value = self.test_password
        
        # Encrypt the file
        encrypt_file(
            input_file=self.test_plaintext_file,
            output_file=self.test_encrypted_file,
            password=self.test_password,
            settings=KDF_SETTINGS,
            password_was_generated=False
        )
        
        # Get list of files before decryption
        files_before = set(os.listdir(self.test_dir))
        
        # Decrypt the file
        decrypt_file(
            input_file=self.test_encrypted_file,
            output_file=self.test_decrypted_file,
            verify_report_path=None,
            password=self.test_password,
            force_insecure=False
        )
        
        # Get list of files after decryption
        files_after = set(os.listdir(self.test_dir))
        
        # Check for any unexpected temporary files
        new_files = files_after - files_before
        # Should only contain the decrypted file and possibly a report
        temp_files = [f for f in new_files if f.startswith('tmp') or 'temp' in f.lower()]
        
        self.assertEqual(len(temp_files), 0,
                        f"No temporary files should remain after successful decryption, found: {temp_files}")
    
    @patch('encrypt_app.input', return_value='y')
    @patch('encrypt_app.get_verified_password')
    @patch('builtins.print')
    def test_decrypt_file_preserves_binary_content(self, mock_print, mock_get_password, mock_input):
        """Test that decrypt_file correctly handles binary content (not just text)."""
        # Mock password input
        mock_get_password.return_value = self.test_password
        
        # Create binary content with various byte values
        binary_content = bytes(range(256)) * 100  # All possible byte values
        
        binary_file = Path(self.test_dir) / "binary_test.bin"
        with open(binary_file, 'wb') as f:
            f.write(binary_content)
        
        binary_encrypted = Path(self.test_dir) / f"binary_test{ENCRYPTED_FILE_SUFFIX}"
        binary_decrypted = Path(self.test_dir) / "binary_decrypted.bin"
        
        # Encrypt the binary file
        encrypt_file(
            input_file=binary_file,
            output_file=binary_encrypted,
            password=self.test_password,
            settings=KDF_SETTINGS,
            password_was_generated=False
        )
        
        # Decrypt the binary file
        decrypt_file(
            input_file=binary_encrypted,
            output_file=binary_decrypted,
            verify_report_path=None,
            password=self.test_password,
            force_insecure=False
        )
        
        # Verify binary content matches exactly
        with open(binary_decrypted, 'rb') as f:
            decrypted_content = f.read()
        
        self.assertEqual(decrypted_content, binary_content,
                        "Decrypted binary content should match original exactly")


if __name__ == '__main__':
    unittest.main()
