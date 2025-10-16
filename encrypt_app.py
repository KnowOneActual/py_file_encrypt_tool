import argparse
import sys
import os
import json
from datetime import datetime
from getpass import getpass
from pathlib import Path

# --- Core Cryptography Imports ---
# AESGCM provides authenticated encryption (confidentiality + integrity)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# Argon2id is the recommended Key Derivation Function (KDF)
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

# --- Configuration Constants (Secure Defaults / File Format) ---
FILE_VERSION_HEADER = b"PYENC_V1" # Simple header for versioning and file identification
ENCRYPTED_FILE_SUFFIX = ".enc"
REPORT_FILE_SUFFIX = ".report.json"
AES_KEY_SIZE = 32 # 256 bits for AES-256
GCM_NONCE_LENGTH = 12
ARGON2_SALT_LENGTH = 16

# Secure KDF settings (Argon2id default parameters)
KDF_SETTINGS = {
    'algorithm': 'Argon2id',
    'time_cost': 4,        # Number of iterations
    'memory_cost': 65536,  # Memory in KiB (64 MiB)
    'parallelism': 4       # Number of threads/lanes
}

# --- Helper Functions ---

def derive_key(password: str, salt: bytes, settings: dict) -> bytes:
    """Derives a strong cryptographic key using Argon2id."""
    
    # We use Argon2id here, prioritizing security over other options.
    kdf = Argon2id(
        salt=salt,
        time_cost=settings['time_cost'],
        memory_cost=settings['memory_cost'],
        parallelism=settings['parallelism']
    )
    # Derive a 32-byte key for AES-256
    key = kdf.derive(password.encode('utf-8'), length=AES_KEY_SIZE) 
    return key


def generate_report(input_file: Path, output_file: Path, report_data: dict):
    """Generates a JSON report detailing the encryption settings."""
    
    report_path = input_file.with_suffix(REPORT_FILE_SUFFIX)
    
    # Add metadata
    report_data['original_file'] = input_file.name
    report_data['encrypted_file'] = output_file.name
    report_data['timestamp'] = datetime.utcnow().isoformat() + "Z"
    
    # Clean up byte values for JSON serialization
    report_data['salt'] = report_data['salt'].hex()
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
# This function is crucial and needs to be implemented next.

def decrypt_file(input_path: str, output_path: str, password: str):
    """
    Handles the main decryption logic by reading the header, deriving the key,
    and decrypting/authenticating the ciphertext.
    """
    input_file = Path(input_path)
    
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
        default=KDF_SETTINGS['time_cost'],
        help=f"Time cost (iterations) for Argon2id. Default: {KDF_SETTINGS['time_cost']}"
    )
    custom_settings_group.add_argument(
        '--kdf-parallelism',
        type=int,
        default=KDF_SETTINGS['parallelism'],
        help=f"Parallelism (threads/lanes) for Argon2id. Default: {KDF_SETTINGS['parallelism']}"
    )


    args = parser.parse_args()
    
    # Get password securely using getpass
    password = getpass("Enter password: ")
    if not password:
        print("Error: Password cannot be empty.", file=sys.stderr)
        sys.exit(1)

    # Combine KDF settings from defaults and user overrides
    kdf_settings = KDF_SETTINGS.copy()
    kdf_settings['memory_cost'] = args.kdf_memory
    kdf_settings['time_cost'] = args.kdf_time
    kdf_settings['parallelism'] = args.kdf_parallelism

    if args.encrypt:
        # Easy Button Mode uses the defaults if custom flags aren't set
        encrypt_file(args.encrypt, args.output, password, kdf_settings)
    elif args.decrypt:
        # Decryption only needs the file path and password
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