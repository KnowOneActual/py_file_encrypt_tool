import argparse
import sys
import os
import json
from datetime import datetime, timezone 
from getpass import getpass
from pathlib import Path
import struct
# NEW IMPORTS FOR STREAMING AND CRYPTO
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidTag

# --- Configuration Constants (Secure Defaults / File Format) ---
FILE_VERSION_HEADER = b"PYENC_V1" 
ENCRYPTED_FILE_SUFFIX = ".enc"
REPORT_FILE_SUFFIX = ".report.json"
AES_KEY_SIZE = 32 # 256 bits for AES-256
GCM_NONCE_LENGTH = 12
GCM_TAG_SIZE = 16 # NEW: Added constant for the tag size
ARGON2_SALT_LENGTH = 16
MIN_PASSWORD_LENGTH = 8 
CHUNK_SIZE = 65536 # 64 KB read/write buffer size for streaming

# Size of the KDF parameters header: 3 unsigned integers (I)
KDF_HEADER_FORMAT = '<III'
KDF_HEADER_SIZE = struct.calcsize(KDF_HEADER_FORMAT) # 12 bytes

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
        password = getpass(f"Enter password (min {MIN_PASSWORD_LENGTH} characters): ")
        if not password:
            print("Error: Password cannot be empty.", file=sys.stderr)
            continue
        
        if len(password) < MIN_PASSWORD_LENGTH:
            print(f"Error: Password must be at least {MIN_PASSWORD_LENGTH} characters long.", file=sys.stderr)
            continue
            
        password_confirm = getpass("Confirm password: ")
        
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
    
    report_path = input_file.with_suffix(REPORT_FILE_SUFFIX)
    
    report_data['original_file'] = input_file.name
    report_data['encrypted_file'] = output_file.name
    report_data['timestamp'] = datetime.now(timezone.utc).isoformat() 
    
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
    Encrypts the file using AES-256-GCM, streaming data in chunks.
    The output file format is: [HEADER][KDF_PARAMS][SALT][NONCE][CIPHERTEXT][TAG]
    """
    
    input_file = Path(input_path).resolve()
    
    if not output_path:
        output_file = input_file.with_suffix(input_file.suffix + ENCRYPTED_FILE_SUFFIX)
    else:
        output_file = Path(output_path).resolve()

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

    # 3. Initialize the streaming cipher object
    try:
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        ).encryptor()
        
        # We process the AAD first
        aad = FILE_VERSION_HEADER 
        encryptor.authenticate_additional_data(aad)

        # 4. Create the KDF parameter header
        kdf_params_header = struct.pack(
            KDF_HEADER_FORMAT,
            settings['memory_cost'],
            settings['iterations'],
            settings['lanes']
        )
    except Exception as e:
        print(f"Error preparing encryption: {e}", file=sys.stderr)
        return

    # 5. Write the file header components
    try:
        with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
            f_out.write(FILE_VERSION_HEADER)
            f_out.write(kdf_params_header)
            f_out.write(salt)
            f_out.write(nonce)
            
            # 6. Stream file content and encrypt chunk by chunk
            while True:
                chunk = f_in.read(CHUNK_SIZE)
                if len(chunk) == 0:
                    break
                
                # Encrypt the chunk and write it out
                f_out.write(encryptor.update(chunk))

            # 7. Finalize the encryption and write the Authentication Tag
            f_out.write(encryptor.finalize())
            f_out.write(encryptor.tag) # GCM tag is stored separately
            
        print(f"Encryption successful. Output: {output_file}")
        
        # 8. Generate Report
        report_data = {'kdf_settings': settings, 'algorithm': 'AES-256-GCM', 'salt': salt, 'nonce': nonce}
        generate_report(input_file, output_file, report_data)

    except FileNotFoundError:
        print(f"Error: Input file not found at '{input_file}'", file=sys.stderr)
        return
    except Exception as e:
        print(f"Error during file streaming: {e}", file=sys.stderr)
        if output_file.exists():
            os.remove(output_file)
        return


# ----------------- Decryption Logic Implementation (Streaming) -----------------

def decrypt_file(input_path: str, output_path: str, password: str):
    """
    Handles the main decryption logic: reads KDF parameters, derives the key,
    and streams the decryption/authentication process.
    """
    input_file = Path(input_path).resolve()
    
    if not input_file.name.endswith(ENCRYPTED_FILE_SUFFIX):
        print(f"Error: Decryption file must end with '{ENCRYPTED_FILE_SUFFIX}' suffix.", file=sys.stderr)
        return
        
    if not output_path:
        base_name = input_file.name.removesuffix(ENCRYPTED_FILE_SUFFIX)
        output_file = input_file.parent / base_name
    else:
        output_file = Path(output_path).resolve()
        
    print(f"Decrypting '{input_file.name}' to '{output_file}'...")
    
    try:
        with open(input_file, 'rb') as f_in:
            # 1. Read and verify Header
            header = f_in.read(len(FILE_VERSION_HEADER))
            if header != FILE_VERSION_HEADER:
                print("Error: Invalid file header. This file may be corrupt or not created by this tool.", file=sys.stderr)
                return
            
            # 2. Read and unpack KDF Parameters
            kdf_params_header = f_in.read(KDF_HEADER_SIZE)
            if len(kdf_params_header) != KDF_HEADER_SIZE:
                print("Error: Encrypted file is incomplete (missing KDF parameters).", file=sys.stderr)
                return

            memory_cost, iterations, lanes = struct.unpack(KDF_HEADER_FORMAT, kdf_params_header)
            
            kdf_settings_from_file = {
                'algorithm': 'Argon2id',
                'memory_cost': memory_cost,
                'iterations': iterations,
                'lanes': lanes
            }
            
            # 3. Read Metadata (Salt and Nonce/IV)
            salt = f_in.read(ARGON2_SALT_LENGTH)
            nonce = f_in.read(GCM_NONCE_LENGTH)
            
            if len(salt) != ARGON2_SALT_LENGTH or len(nonce) != GCM_NONCE_LENGTH:
                print("Error: Encrypted file is incomplete (missing salt or nonce).", file=sys.stderr)
                return
            
            # 4. Derive the key
            key = derive_key(password, salt, kdf_settings_from_file)
            
            # 5. Calculate tag position and read the tag
            file_size = os.path.getsize(input_file)
            tag_start_position = file_size - GCM_TAG_SIZE
            
            min_size = len(FILE_VERSION_HEADER) + KDF_HEADER_SIZE + ARGON2_SALT_LENGTH + GCM_NONCE_LENGTH + GCM_TAG_SIZE
            if file_size < min_size:
                 print("Error: Encrypted file is too small to be a valid container.", file=sys.stderr)
                 return

            # Read the tag from the end of the file
            f_in.seek(tag_start_position)
            tag = f_in.read(GCM_TAG_SIZE)
            
            # Go back to the start of the ciphertext
            start_of_ciphertext = len(FILE_VERSION_HEADER) + KDF_HEADER_SIZE + ARGON2_SALT_LENGTH + GCM_NONCE_LENGTH
            f_in.seek(start_of_ciphertext) 

            # 6. Initialize the streaming decryptor
            decryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, tag), # Provide the tag to the mode
                backend=default_backend()
            ).decryptor()

            # Process the AAD first
            aad = FILE_VERSION_HEADER
            decryptor.authenticate_additional_data(aad)
            
            # 7. Stream file content and decrypt chunk by chunk
            with open(output_file, 'wb') as f_out:
                bytes_to_read = tag_start_position - start_of_ciphertext
                
                while bytes_to_read > 0:
                    read_size = min(CHUNK_SIZE, bytes_to_read)
                    chunk = f_in.read(read_size)
                    
                    if not chunk: 
                        break 
                        
                    f_out.write(decryptor.update(chunk))
                    bytes_to_read -= len(chunk)

                # 8. Finalize the decryption (verifies the tag)
                f_out.write(decryptor.finalize())
            
        print(f"Decryption successful. Output: {output_file}")
    
    except InvalidTag:
        print("Error: Decryption failed. Incorrect password or the file has been tampered with.", file=sys.stderr)
        if output_file.exists():
            os.remove(output_file)
        return
    except FileNotFoundError:
        print(f"Error: Encrypted file not found at '{input_file}'", file=sys.stderr)
        return
    except struct.error as e:
        print(f"Error parsing file header: {e}. File structure may be invalid.", file=sys.stderr)
        return
    except Exception as e:
        print(f"An unexpected error occurred during decryption: {e}", file=sys.stderr)
        return

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
    
    # Password handling logic
    if args.encrypt:
        password = get_verified_password()
    elif args.decrypt:
        password = getpass("Enter password: ")
        if len(password) < MIN_PASSWORD_LENGTH:
            print(f"Error: Decryption password must be at least {MIN_PASSWORD_LENGTH} characters long.", file=sys.stderr)
            sys.exit(1)


    # Combine KDF settings
    kdf_settings = KDF_SETTINGS.copy()
    kdf_settings['memory_cost'] = args.kdf_memory
    kdf_settings['iterations'] = args.kdf_time
    kdf_settings['lanes'] = args.kdf_parallelism

    if args.encrypt:
        encrypt_file(args.encrypt, args.output, password, kdf_settings)
    elif args.decrypt:
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