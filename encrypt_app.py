import argparse
import sys
from cryptography.hazmat.primitives.kdf.argon2 import Argon2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Configuration Constants (Best Practices) ---
# These are the "Secure Defaults" for the Easy Button mode.
DEFAULT_ALGORITHM = "AES-256-GCM"
DEFAULT_KDF = "Argon2id"
ARGON2_SALT_LENGTH = 16
ARGON2_TIME_COST = 4
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 4

# --- Helper Functions (To be implemented) ---

def generate_report(file_path, settings):
    """Generates a detailed report of the encryption operation."""
    # TODO: Implement report generation logic (JSON or text)
    print(f"Report generated for {file_path}.enc using {settings['kdf']}.")
    pass

def encrypt_file(input_path, output_path, password, settings):
    """Handles the main encryption logic."""
    print(f"Encrypting '{input_path}' with {settings['algorithm']}...")
    
    # 1. Password Derivation (KDF)
    # 2. Key/IV generation
    # 3. File streaming and encryption (using AESGCM)
    # 4. Write data, IV, and tag to output_path
    
    # After successful encryption:
    generate_report(input_path, settings)
    print("Encryption complete.")

def decrypt_file(input_path, output_path, password):
    """Handles the main decryption logic."""
    print(f"Decrypting '{input_path}'...")
    # 1. Read key derivation parameters from file header
    # 2. Derive key using password and parameters
    # 3. Decrypt and verify (using AESGCM authentication tag)
    print("Decryption complete.")


# --- Main CLI Logic ---

def main():
    parser = argparse.ArgumentParser(
        description="A secure, cross-platform CLI tool for file encryption.",
        epilog="Use the easy button (--encrypt) for secure defaults, or customize settings for advanced control."
    )
    
    # Mutually Exclusive Group: You must choose either Encrypt or Decrypt
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '--encrypt',
        metavar='FILE',
        type=str,
        help='Encrypt the specified file using secure defaults.'
    )
    group.add_argument(
        '--decrypt',
        metavar='FILE.enc',
        type=str,
        help='Decrypt the specified encrypted file.'
    )

    # Output Argument
    parser.add_argument(
        '-o', '--output',
        type=str,
        help='Specify the output file path. Defaults to [INPUT].enc or [INPUT_BASE].dec.'
    )

    # --- Custom Settings (For the advanced user) ---
    custom_settings = parser.add_argument_group('Custom Encryption Settings', 'These settings override the secure defaults.')
    custom_settings.add_argument(
        '--algorithm',
        type=str,
        default=DEFAULT_ALGORITHM,
        choices=['AES-256-GCM', 'ChaCha20-Poly1305'],
        help=f"Encryption algorithm to use. Default: {DEFAULT_ALGORITHM}"
    )
    custom_settings.add_argument(
        '--kdf',
        type=str,
        default=DEFAULT_KDF,
        choices=['Argon2id', 'PBKDF2'],
        help=f"Key Derivation Function to use. Default: {DEFAULT_KDF}"
    )
    # You can add more detailed KDF parameters here later (e.g., --kdf-iterations)


    args = parser.parse_args()
    
    # A simple way to handle password input securely
    password = input("Enter password: ")

    # Set up the encryption settings dictionary
    settings = {
        'algorithm': args.algorithm,
        'kdf': args.kdf,
        # Add other KDF parameters here
    }

    if args.encrypt:
        # Easy Button Mode is automatically handled by the default values
        encrypt_file(args.encrypt, args.output, password, settings)
    elif args.decrypt:
        # Decryption only needs the file path and password
        decrypt_file(args.decrypt, args.output, password)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)
        sys.exit(1)