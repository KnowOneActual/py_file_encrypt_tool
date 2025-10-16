import argparse
import sys
import os
import json
# Updated imports for timezone-aware datetime
from datetime import datetime, timezone 
from getpass import getpass
from pathlib import Path

# --- Core Cryptography Imports ---
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

# --- Configuration Constants (Secure Defaults / File Format) ---
FILE_VERSION_HEADER = b"PYENC_V1" 
ENCRYPTED_FILE_SUFFIX = ".enc"
REPORT_FILE_SUFFIX = ".report.json"
AES_KEY_SIZE = 32 # 256 bits for AES-256
GCM_NONCE_LENGTH = 12
ARGON2_SALT_LENGTH = 16
# UPDATED: Security enforcement constant
MIN_PASSWORD_LENGTH = 8 

# Secure KDF settings (Argon2id default parameters)
KDF_SETTINGS = {
    'algorithm': 'Argon2id',
    'iterations': 4,        # Time cost
    'memory_cost': 65536,   # Memory cost in KiB (64 MiB)
    'lanes': 4              # Parallelism (threads/lanes)
}

# --- Helper Functions ---

def get_verified_password():
    """Prompts the user for a password twice, enforces minimum length, and verifies they match."""
    while True:
        # Prompt user with updated minimum length requirement
        password = getpass(f"Enter password (min {MIN_PASSWORD_LENGTH} characters): ")
        if not password:
            print("Error: Password cannot be empty.", file=sys.stderr)
            continue
        
        # Check minimum length
        if len(password) < MIN_PASSWORD_LENGTH:
            print(f"Error: Password must be at least {MIN_PASSWORD_LENGTH} characters long.", file=sys.stderr)
            continue
            
        password_confirm = getpass("Confirm password: ")
        
        # Verify passwords match
        if password == password_confirm:
            return password
        else:
            print("Error: Passwords do not match. Please try again.", file=sys.stderr)


def derive_key(password: str, salt: bytes, settings: dict) -> bytes:
    """Derives a strong cryptographic key using Argon2id."""
    
    kdf = Argon2id(
        salt=salt,
        length=AES_KEY_SIZE, 
        iterations=settings['iterations'],
        memory_cost=settings['memory_cost'],
        lanes=settings['lanes']
    )
    key = kdf.derive(password.encode('utf-8')) 
    return key


def generate_report(input_file: Path, output_file: Path, report_data: dict):
    """Generates a JSON report detailing the encryption settings."""
    
    # Determine the report file path (e.g., tests/text.report.json)
    report_path = input_file.with_suffix(REPORT_FILE_SUFFIX)
    
    # Add metadata
    report_data['original_file'] = input_file.name
    report_data['encrypted_file'] = output_file.name
    # FIX: Use datetime.now(timezone.utc) to resolve DeprecationWarning
    report_data['timestamp'] = datetime.now(timezone.utc).isoformat() 
    
    # Clean up byte values for JSON serialization
    if isinstance(report_data.get('salt'), bytes):
        report_data['salt'] = report_data['salt'].hex()
    if isinstance(report_data.get('nonce'), bytes):
        report_data['nonce'] = report_data['nonce'].hex()

    try:
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=4)
        print(f"Report generated successfully: {report_path}")
    except Exception as e:
        print(f"Warning: Could not write encryption report: {e}", file=sys.stderr)


def encrypt_file(input_path: str, output_path: str, password: str, settings: dict):
    """
    Encrypts the file using AES-256-GCM and the derived key.
    The output file format is: [HEADER][SALT][NONCE][CIPHERTEXT + TAG]
    """
    
    input_file = Path(input_path)
    if not output_path:
        output_file = input_file.with_suffix(input_file.suffix + ENCRYPTED_FILE_SUFFIX)
    else:
        output_file = Path(output_path)

    print(f"Starting encryption of '{input_file.name}'...")
    
    # 1. Generate unique random values
    salt = os.urandom(ARGON2_SALT_LENGTH)
    nonce = os.urandom(GCM_NONCE_LENGTH)

    # 2. Derive the key
    try:
        key = derive_key(password, salt, settings)
    except Exception as e:
        print(f"Error during key derivation: {e}", file=sys.stderr)
        return

    # 3. Initialize the cipher
    aesgcm = AESGCM(key)
    
    # 4. Read file content and encrypt (using a single read for simplicity)
    try:
        with open(input_file, 'rb') as f_in:
            plaintext = f_in.read()
            
        # The AAD (Additional Authenticated Data) authenticates the file header
        aad = FILE_VERSION_HEADER 
        
        # Encrypt. The result contains the ciphertext AND the 16-byte authentication tag appended.
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad)
        
    except FileNotFoundError:
        print(f"Error: Input file not found at '{input_path}'", file=sys.stderr)
        return
    except Exception as e:
        print(f"Error during encryption process: {e}", file=sys.stderr)
        return

    # 5. Write the final encrypted file
    try:
        with open(output_file, 'wb') as f_out:
            # Write Header (for file identification)
            f_out.write(FILE_VERSION_HEADER)
            
            # Write KDF Metadata (salt)
            f_out.write(salt)
            
            # Write Nonce (IV)
            f_out.write(nonce)
            
            # Write Ciphertext + Tag
            f_out.write(ciphertext_with_tag)
            
        print(f"Encryption successful. Output: {output_file}")
        
        # 6. Generate Report
        report_data = {'kdf_settings': settings, 'algorithm': 'AES-256-GCM', 'salt': salt, 'nonce': nonce}
        generate_report(input_file, output_file, report_data)

    except Exception as e:
        print(f"Error writing output file: {e}", file=sys.stderr)
        # IMPORTANT: Clean up partially written file if possible
        if output_file.exists():
            os.remove(output_file)
        return

# ----------------- Decryption Logic Placeholder -----------------

def decrypt_file(input_path: str, output_path: str, password: str):
    """
    Handles the main decryption logic by reading the header, deriving the key,
    and decrypting/authenticating the ciphertext.
    """
    input_file = Path(input_path)
    
    if not input_file.name.endswith(ENCRYPTED_FILE_SUFFIX):
        print(f"Error: Decryption file must end with '{ENCRYPTED_FILE_SUFFIX}' suffix.", file=sys.stderr)
        return

    if not output_path:
        # Default output name: remove all suffixes starting from the .enc
        base_name = input_file.name.removesuffix(ENCRYPTED_FILE_SUFFIX)
        output_file = input_file.parent / base_name
    else:
        output_file = Path(output_path)
        
    print(f"Decrypting '{input_file.name}' to '{output_file}'...")
    print("TODO: Decryption logic needs to be implemented here.")

# ----------------------------------------------------------------

# --- Main CLI Logic ---

def main():
    parser = argparse.ArgumentParser(
        description="A secure, cross-platform CLI tool for file encryption.",
        epilog="Use the --encrypt command for secure defaults (Easy Button), or use optional flags for custom settings."
    )
    
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

    parser.add_argument(
        '-o', '--output',
        type=str,
        help='Specify the output file path. Defaults to [INPUT].enc (encrypt) or [INPUT_BASE] (decrypt).'
    )

    # --- Custom Settings (For the advanced user) ---
    custom_settings_group = parser.add_argument_group(
        'Custom KDF Settings (Advanced)', 
        'These settings override the Argon2id parameters for specialized use.'
    )
    custom_settings_group.add_argument(
        '--kdf-memory',
        type=int,
        default=KDF_SETTINGS['memory_cost'], 
        help=f"Memory cost for Argon2id in KiB. Default: {KDF_SETTINGS['memory_cost']}"
    )
    custom_settings_group.add_argument(
        '--kdf-time',
        type=int,
        default=KDF_SETTINGS['iterations'], 
        help=f"Time cost (iterations) for Argon2id. Default: {KDF_SETTINGS['iterations']}"
    )
    custom_settings_group.add_argument(
        '--kdf-parallelism',
        type=int,
        default=KDF_SETTINGS['lanes'], 
        help=f"Parallelism (threads/lanes) for Argon2id. Default: {KDF_SETTINGS['lanes']}"
    )


    args = parser.parse_args()
    
    # Get password via the secure, verified function
    password = get_verified_password()

    # Combine KDF settings, mapping the CLI arg values to the function's required internal names
    kdf_settings = KDF_SETTINGS.copy()
    kdf_settings['memory_cost'] = args.kdf_memory
    kdf_settings['iterations'] = args.kdf_time
    kdf_settings['lanes'] = args.kdf_parallelism

    if args.encrypt:
        # Encryption is fully implemented for this prototype stage
        encrypt_file(args.encrypt, args.output, password, kdf_settings)
    elif args.decrypt:
        # Decryption is the next big step!
        decrypt_file(args.decrypt, args.output, password)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)