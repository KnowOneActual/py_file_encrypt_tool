import argparse
import sys
import os
import json
import secrets
import string
import tempfile
from datetime import datetime, timezone 
from getpass import getpass
from pathlib import Path
import struct
import hashlib

# --- Core Cryptography Imports ---
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidTag

# --- Configuration Constants (Updated) ---
FILE_VERSION_HEADER = b"PYENC_V1" 
ENCRYPTED_FILE_SUFFIX = ".enc"
REPORT_FILE_SUFFIX = ".report.json"
# NEW CORRUPTION CONSTANT
CORRUPTION_SUFFIX = ".unverified_corrupt" 
AES_KEY_SIZE = 32 # 256 bits for AES-256
GCM_NONCE_LENGTH = 12
GCM_TAG_SIZE = 16 
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

CHECKSUM_ALGORITHM = "SHA-256"

# --- Helper Functions ---

def validate_and_resolve_path(user_path_str: str | None, operation_name: str, check_exists: bool = False) -> Path | None:
    """
    Safely resolves a user-provided path, ensuring it is at or under the CWD.
    This prevents Path Traversal attacks by checking for malicious components *before* use.
    Raises SystemExit on failure.
    """
    if not user_path_str:
        return None

    # --- EXPLICIT SANITIZATION CHECKS (for Snyk) ---
    # 1. Disallow absolute paths.
    try:
        # We create a new path object here just for this check.
        # This check is what Snyk *should* see as a sanitizer.
        temp_path = Path(user_path_str)
        if temp_path.is_absolute():
            print(f"Error: Absolute paths are not allowed for {operation_name}.", file=sys.stderr)
            print(f"Path Provided: {user_path_str}", file=sys.stderr)
            print("Operation aborted for security.", file=sys.stderr)
            sys.exit(1)
    except Exception as e:
        # Catch invalid path strings (e.g., with null bytes)
        print(f"Error: Invalid path string for {operation_name}: {e}", file=sys.stderr)
        sys.exit(1)

    # 2. Check for ".." components in the string itself.
    path_components = user_path_str.split(os.sep)
    if ".." in path_components:
        print(f"Error: Path traversal components ('..') are not allowed for {operation_name}.", file=sys.stderr)
        print(f"Path Provided: {user_path_str}", file=sys.stderr)
        print("Operation aborted for security.", file=sys.stderr)
        sys.exit(1)
    # --- END EXPLICIT CHECKS ---

    # 3. Get the trusted base directory.
    cwd = Path.cwd().resolve()
    
    # 4. "Safely Join" the trusted base with the (now-checked) user path.
    combined_path = cwd.joinpath(user_path_str)

    # 5. Resolve the *combined* path. This cleans up 'foo/bar/../baz'
    try:
        resolved_path = combined_path.resolve()
    except Exception as e:
        print(f"Error: Could not resolve path for {operation_name}: {e}", file=sys.stderr)
        sys.exit(1)

    # 6. Final, critical check: Ensure the *resolved* path is still inside the CWD.
    try:
        resolved_path.relative_to(cwd)
    except ValueError:
        print(f"Error: Path for {operation_name} is outside the current directory.", file=sys.stderr)
        print(f"Resolved Path: {resolved_path}", file=sys.stderr)
        print("Operation aborted for security.", file=sys.stderr)
        sys.exit(1)
        
    if check_exists and not resolved_path.exists():
        print(f"Error: Input file for {operation_name} not found.", file=sys.stderr)
        print(f"Path: {resolved_path}", file=sys.stderr)
        sys.exit(1)

    return resolved_path


def generate_secure_password(length: int) -> str:
    """Generates a cryptographically secure password between 10-20 characters."""
    if not 10 <= length <= 20:
        raise ValueError("Password length must be between 10 and 20 characters.")
        
    alphabet = string.ascii_letters + string.digits
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password

def load_original_checksum(report_path: Path) -> tuple[str, str] | None:
    """Reads the original checksum and algorithm from the JSON report. (Receives validated path)"""
    try:
        with open(report_path, 'r') as f: # nosec B310 - Path is sanitized by validate_and_resolve_path
            report_data = json.load(f)
        
        checksum_data = report_data.get('original_checksum')
        if checksum_data and isinstance(checksum_data, dict):
            return checksum_data.get('hash'), checksum_data.get('algorithm')
        else:
            print("Error: Report file does not contain checksum data.", file=sys.stderr)
            return None
    except FileNotFoundError:
        print(f"Error: Verification report not found at '{report_path}'.", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error reading verification report: {e}", file=sys.stderr)
        return None


def calculate_file_checksum(file_path: Path, chunk_size: int) -> str:
    """Calculates the SHA-256 checksum of a file efficiently. (Receives validated path)"""
    hasher = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f: # nosec B310 - Path is sanitized by validate_and_resolve_path
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        print(f"Error calculating checksum for output file: {e}", file=sys.stderr)
        return ""


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


def generate_report(input_file: Path, output_file: Path, report_data: dict, generated_password: str | None = None) -> Path | None:
    """Generates a JSON report. (Receives validated paths)"""
    
    # This is safe as input_file is already a validated Path
    report_path = input_file.with_suffix(REPORT_FILE_SUFFIX)
    
    report_data['original_file'] = input_file.name
    report_data['encrypted_file'] = output_file.name
    report_data['timestamp'] = datetime.now(timezone.utc).isoformat() 
    
    if generated_password:
        report_data['generated_password'] = generated_password

    if isinstance(report_data.get('salt'), bytes):
        report_data['salt'] = report_data['salt'].hex()
    if isinstance(report_data.get('nonce'), bytes):
        report_data['nonce'] = report_data['nonce'].hex()

    try:
        # This open() is now safe as report_path is derived from a validated path
        with open(report_path, 'w') as f: # nosec B310 - Path is sanitized by validate_and_resolve_path
            json.dump(report_data, f, indent=4)
        print(f"Report generated successfully: {report_path}")
        return report_path
    except Exception as e:
        print(f"Warning: Could not write encryption report: {e}", file=sys.stderr)
        return None


def encrypt_file(input_file: Path, output_file: Path | None, password: str, settings: dict, password_was_generated: bool = False):
    """
    Encrypts the file using AES-256-GCM, streaming data in chunks.
    (input_file and output_file are pre-validated Path objects from main())
    """
    
    # Use pre-validated output_file, or derive from pre-validated input_file
    if not output_file:
        output_file = input_file.with_suffix(input_file.suffix + ENCRYPTED_FILE_SUFFIX)

    # --- Overwrite Protection ---
    if output_file.exists():
        answer = input(f"Warning: Output file '{output_file.name}' already exists. Overwrite? (y/N) ")
        if answer.lower() != 'y':
            print("Encryption aborted by user.", file=sys.stderr)
            return

    print(f"Starting encryption of '{input_file.name}'...")
    
    # 1. Calculate the checksum (Safe, input_file is validated)
    original_checksum = calculate_file_checksum(input_file, CHUNK_SIZE)
    if not original_checksum:
        print("Error: Could not generate file checksum. Aborting encryption.", file=sys.stderr)
        return

    # 2. Generate unique random values and derive key
    salt = os.urandom(ARGON2_SALT_LENGTH)
    nonce = os.urandom(GCM_NONCE_LENGTH)
    try:
        key = derive_key(password, salt, settings)
    except Exception as e:
        print(f"Error during key derivation: {e}", file=sys.stderr)
        return

    # 3. Create the KDF parameter header
    try:
        kdf_params_header = struct.pack(
            KDF_HEADER_FORMAT,
            settings['memory_cost'],
            settings['iterations'],
            settings['lanes']
        )
    except Exception as e:
        print(f"Error packing KDF parameters: {e}", file=sys.stderr)
        return
        
    # Expanded AAD includes the entire header
    aad = FILE_VERSION_HEADER + kdf_params_header + salt + nonce 

    # 4. Initialize streaming cipher object
    try:
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        ).encryptor()
        
        encryptor.authenticate_additional_data(aad)

    except Exception as e:
        print(f"Error preparing encryption: {e}", file=sys.stderr)
        return

    # 5. Write file components and stream data
    try:
        # These file operations are now safe
        with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out: # nosec B310 - Paths are sanitized
            # Write all AAD components to the file for decryption to read
            f_out.write(FILE_VERSION_HEADER)
            f_out.write(kdf_params_header)
            f_out.write(salt)
            f_out.write(nonce)
            
            # Stream file content and encrypt chunk by chunk
            while True:
                chunk = f_in.read(CHUNK_SIZE)
                if len(chunk) == 0:
                    break
                f_out.write(encryptor.update(chunk))

            f_out.write(encryptor.finalize())
            f_out.write(encryptor.tag)
            
        print(f"Encryption successful. Output: {output_file}")
        
        # 6. Generate Report (Safe, paths are validated)
        report_data = {
            'kdf_settings': settings, 
            'algorithm': 'AES-256-GCM', 
            'salt': salt, 
            'nonce': nonce,
            'original_checksum': {'algorithm': CHECKSUM_ALGORITHM, 'hash': original_checksum}
        }
        
        gen_pass_arg = password if password_was_generated else None
        report_path = generate_report(input_file, output_file, report_data, generated_password=gen_pass_arg)

        # 7. Print warning if password was generated
        if password_was_generated and report_path:
            print("\n" + "="*80)
            print("⚠️ ⚠️  PASSWORD GENERATED AND SAVED IN REPORT ⚠️ ⚠️")
            print(f"A new secure password was generated for this file.")
            print(f"It has been saved in the JSON report: {report_path}")
            print("WARNING: This is your ONLY copy. Secure this report file.")
            print("If you lose the report, you will lose access to the encrypted file.")
            print("="*80 + "\n")

    except FileNotFoundError:
        print(f"Error: Input file not found at '{input_file}'", file=sys.stderr)
        return
    except Exception as e:
        print(f"Error during file streaming: {e}", file=sys.stderr)
        if output_file.exists():
            os.remove(output_file) # nosec B310 - Path is sanitized
        return


def decrypt_file(input_file: Path, output_file: Path | None, verify_report_path: Path | None, password: str, force_insecure: bool):
    """
    Handles the main decryption logic.
    (All path args are pre-validated Path objects from main())
    """
    
    if not output_file:
        # Safe, derived from validated input_file
        base_name = input_file.name.removesuffix(ENCRYPTED_FILE_SUFFIX)
        output_file = input_file.parent / base_name
    else:
        # output_file is already a validated Path
        pass 
        
    # --- MODIFIED: Use tempfile ---
    temp_file_path = None # Store path for cleanup
        
    print(f"Decrypting '{input_file.name}' to '{output_file}'...")
    
    if force_insecure:
        print("\n" + "="*80)
        print("⚠️ ⚠️  SECURITY WARNING: INSECURE DECRYPT MODE ACTIVE ⚠️ ⚠️")
        print("Integrity check failures (wrong password or tampering) will be ignored,")
        print("and the unverified, corrupted data will be written to the output file.")
        print("="*80 + "\n")

    
    try:
        # --- File Header Read and Decryption Setup ---
        # Safe, input_file is validated
        with open(input_file, 'rb') as f_in: # nosec B310 - Path is sanitized
            # 1. Read and verify Header
            header = f_in.read(len(FILE_VERSION_HEADER))
            if header != FILE_VERSION_HEADER:
                raise ValueError("Invalid file header. This file may be corrupt or not created by this tool.")
            
            # 2. Read and unpack KDF Parameters
            kdf_params_header = f_in.read(KDF_HEADER_SIZE)
            if len(kdf_params_header) != KDF_HEADER_SIZE:
                raise ValueError("Encrypted file is incomplete (missing KDF parameters).")

            memory_cost, iterations, lanes = struct.unpack(KDF_HEADER_FORMAT, kdf_params_header)
            
            kdf_settings_from_file = {
                'algorithm': 'Argon2id', 'memory_cost': memory_cost, 'iterations': iterations, 'lanes': lanes
            }
            
            # 3. Read Metadata (Salt and Nonce/IV)
            salt = f_in.read(ARGON2_SALT_LENGTH)
            nonce = f_in.read(GCM_NONCE_LENGTH)
            
            if len(salt) != ARGON2_SALT_LENGTH or len(nonce) != GCM_NONCE_LENGTH:
                raise ValueError("Encrypted file is incomplete (missing salt or nonce).")
            
            # 4. Derive the key
            key = derive_key(password, salt, kdf_settings_from_file)
            
            # Expanded AAD includes the entire header
            aad = FILE_VERSION_HEADER + kdf_params_header + salt + nonce
            
            # 5. Get tag and set up streaming
            file_size = os.path.getsize(input_file)
            tag_start_position = file_size - GCM_TAG_SIZE
            
            min_size = len(FILE_VERSION_HEADER) + KDF_HEADER_SIZE + ARGON2_SALT_LENGTH + GCM_NONCE_LENGTH + GCM_TAG_SIZE
            if file_size < min_size:
                 raise ValueError("Encrypted file is too small to be a valid container.")

            f_in.seek(tag_start_position)
            tag = f_in.read(GCM_TAG_SIZE)
            
            start_of_ciphertext = len(FILE_VERSION_HEADER) + KDF_HEADER_SIZE + ARGON2_SALT_LENGTH + GCM_NONCE_LENGTH
            f_in.seek(start_of_ciphertext) 

            # 6. Initialize the streaming decryptor
            decryptor = Cipher(
                algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend()
            ).decryptor()

            decryptor.authenticate_additional_data(aad)
            
            # 7. Stream file content and decrypt chunk by chunk
            # --- MODIFIED: Use tempfile ---
            with tempfile.NamedTemporaryFile(dir=output_file.parent, delete=False) as f_out:
                temp_file_path = f_out.name # Store the random path
                
                bytes_to_read = tag_start_position - start_of_ciphertext
                
                while bytes_to_read > 0:
                    read_size = min(CHUNK_SIZE, bytes_to_read)
                    chunk = f_in.read(read_size)
                    
                    if not chunk: break 
                        
                    f_out.write(decryptor.update(chunk))
                    bytes_to_read -= len(chunk)

                # 8. Finalize the decryption (this verifies the GCM tag)
                f_out.write(decryptor.finalize())
        
        # 9. ATOMIC RENAME: Only rename after GCM tag check
        # --- Overwrite Protection ---
        if output_file.exists():
            answer = input(f"Warning: Output file '{output_file.name}' already exists. Overwrite? (y/N) ")
            if answer.lower() != 'y':
                print("Decryption aborted by user.", file=sys.stderr)
                if temp_file_path and Path(temp_file_path).exists():
                    os.remove(temp_file_path) # nosec B310 - Path is sanitized
                return
        
        os.rename(temp_file_path, output_file) # nosec B310 - Paths are sanitized
        temp_file_path = None # Set to None as rename was successful
        
        print(f"Decryption successful. Output: {output_file}")
        
        # 10. "SMART" CHECKSUM VERIFICATION
        verify_path_to_check = verify_report_path # Use the pre-validated Path
        
        # If no verify flag was given, automatically check for a report
        if not verify_path_to_check:
            potential_report_path = input_file.with_suffix(REPORT_FILE_SUFFIX) # Safe
            if potential_report_path.exists():
                print(f"Found report: {potential_report_path.name}")
                answer = input("Verify decrypted file against this report? (Y/n) ")
                if answer.lower() != 'n':
                    verify_path_to_check = potential_report_path # Use the safe, derived path

        if verify_path_to_check:
            # Path is already validated or derived from a validated path
            original_data = load_original_checksum(verify_path_to_check) # Safe
            
            if original_data:
                original_hash, algorithm = original_data
                decrypted_hash = calculate_file_checksum(output_file, CHUNK_SIZE) # Safe
                
                print("\n--- Integrity Verification ---")
                if decrypted_hash == original_hash:
                    print(f"✅ VERIFICATION SUCCESS: Decrypted file {algorithm} matches the original hash in the report.")
                else:
                    print(f"❌ VERIFICATION FAILURE: The decrypted file hash does NOT match the original hash.")
                    print(f"   Original Hash: {original_hash}")
                    print(f"   Decrypted Hash: {decrypted_hash}")
                

    except InvalidTag:
        # Check for the override flag here
        if force_insecure:
            corrupt_output_file = Path(str(output_file) + CORRUPTION_SUFFIX) # Safe
            
            print("\n" + "="*80)
            print("⚠️ SECURITY OVERRIDE ACTIVATED: Corrupted file saved.")
            print("The decryption tag failed. The output file is UNVERIFIED and LIKELY CORRUPTED.")
            print(f"Unverified output saved to: {corrupt_output_file}")
            print("="*80)
            if temp_file_path and Path(temp_file_path).exists():
                 os.rename(temp_file_path, corrupt_output_file) # nosec B310 - Paths are sanitized
                 temp_file_path = None
            return
            
        print("Error: Decryption failed. Incorrect password or the file has been tampered with.", file=sys.stderr)
        if temp_file_path and Path(temp_file_path).exists():
            os.remove(temp_file_path) # nosec B310 - Path is sanitized
        return
    except FileNotFoundError:
        print(f"Error: Required file not found.", file=sys.stderr)
        if temp_file_path and Path(temp_file_path).exists():
            os.remove(temp_file_path) # nosec B310
        return
    except (struct.error, ValueError) as e:
        print(f"Error: File structure invalid or data missing ({e}).", file=sys.stderr)
        if temp_file_path and Path(temp_file_path).exists():
            os.remove(temp_file_path) # nosec B310 - Path is sanitized
        return
    except Exception as e:
        print(f"An unexpected error occurred during decryption: {e}", file=sys.stderr)
        if temp_file_path and Path(temp_file_path).exists():
            os.remove(temp_file_path) # nosec B310 - Path is sanitized
        return

# ----------------------------------------------------------------

# --- Main CLI Logic ---

def main():
    parser = argparse.ArgumentParser(
        description="A secure, cross-platform CLI tool for file encryption.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:

  # 1. Encrypt a file (Easy Button - you will be prompted for a password)
  python encrypt_app.py -e "my_sensitive_data.pdf"

  # 2. Decrypt a file (you will be prompted for a password)
  python encrypt_app.py -d "my_sensitive_data.pdf.enc"

  # 3. Decrypt and verify integrity (auto-finds report)
  python encrypt_app.py -d "file.enc"
  # (If 'file.report.json' exists, it will ask to verify)

  # 4. Decrypt and specify verification report path
  python encrypt_app.py -d "file.enc" -v "file.report.json"

  # 5. Encrypt using a generated password (WARNING: Password saved in .report.json)
  python encrypt_app.py -e "file.txt" -g
  
  # 6. Encrypt using a generated password of a specific length (10-20)
  python encrypt_app.py -e "file.txt" -g 20

  # 7. Encrypt using a password from a script (advanced)
  echo "MySuperSecretP@ssword" | python encrypt_app.py -e "file.txt" --password-stdin
"""
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '-e', '--encrypt',
        metavar='FILE',
        type=str,
        help='Encrypt the specified file using secure defaults.'
    )
    group.add_argument(
        '-d', '--decrypt',
        metavar='FILE.enc',
        type=str,
        help='Decrypt the specified encrypted file.'
    )

    parser.add_argument(
        '-o', '--output',
        type=str,
        help='Specify the output file path. Defaults to [INPUT].enc (encrypt) or [INPUT_BASE] (decrypt).'
    )
    
    parser.add_argument(
        '-v', '--verify-report-path',
        type=str,
        help='(Decrypt Only) Path to the JSON report file to manually verify the decrypted file\'s hash.'
    )
    
    parser.add_argument(
        '-g', '--generate-password',
        nargs='?',
        const=18,
        type=int,
        choices=range(10, 21),
        metavar='LENGTH',
        help='(Encrypt Only) Generate a secure password and save it in the report file. '
             'Default length is 18 if no length is specified. (Range: 10-20)'
    )
    
    parser.add_argument(
        '--password-stdin',
        action='store_true',
        help='(Advanced) Read password from stdin instead of prompting.'
    )

    parser.add_argument(
        '--force-insecure-decrypt',
        action='store_true',
        help='(Decrypt Only) WARNING: Bypasses GCM integrity check on failure. Writes UNVERIFIED, potentially corrupted data.'
    )

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
    
    # --- Updated Password handling logic ---
    password = None
    password_was_generated = False
    
    if args.generate_password and not args.encrypt:
        print("Error: -g/--generate-password can only be used with -e/--encrypt.", file=sys.stderr)
        sys.exit(1)

    if args.password_stdin and args.generate_password:
        print("Error: --password-stdin and -g/--generate-password cannot be used together.", file=sys.stderr)
        sys.exit(1)

    if args.encrypt:
        if args.generate_password:
            pw_length = args.generate_password
            password = generate_secure_password(pw_length)
            password_was_generated = True
            print(f"Generating new {pw_length}-character password...")
        elif args.password_stdin:
            print("Reading password from stdin...", file=sys.stderr)
            password = sys.stdin.readline().strip()
            if len(password) < MIN_PASSWORD_LENGTH:
                 print(f"Error: Password from stdin must be at least {MIN_PASSWORD_LENGTH} characters.", file=sys.stderr)
                 sys.exit(1)
        else:
            password = get_verified_password()
            
    elif args.decrypt:
        if args.password_stdin:
            print("Reading password from stdin...", file=sys.stderr)
            password = sys.stdin.readline().strip()
            if not password:
                 print("Error: Password from stdin cannot be empty.", file=sys.stderr)
                 sys.exit(1)
        else:
            password = getpass("Enter password: ")
            if len(password) < MIN_PASSWORD_LENGTH:
                print(f"Error: Decryption password must be at least {MIN_PASSWORD_LENGTH} characters long.", file=sys.stderr)
                sys.exit(1)
    # --- End Updated Logic ---

    # Combine KDF settings
    kdf_settings = KDF_SETTINGS.copy()
    kdf_settings['memory_cost'] = args.kdf_memory
    kdf_settings['iterations'] = args.kdf_time
    kdf_settings['lanes'] = args.kdf_parallelism

    # --- VALIDATE ALL PATHS IN MAIN ---
    encrypt_input_path = None
    decrypt_input_path = None
    
    if args.encrypt:
        encrypt_input_path = validate_and_resolve_path(args.encrypt, "encrypt input", check_exists=True)
    elif args.decrypt:
        decrypt_input_path = validate_and_resolve_.path(args.decrypt, "decrypt input", check_exists=True)

    # Validate optional paths
    output_path = validate_and_resolve_path(args.output, "output", check_exists=False)
    verify_path = validate_and_resolve_path(args.verify_report_path, "verify report", check_exists=False)
    # --- END VALIDATION ---


    # --- Pass validated Path objects ---
    if args.encrypt:
        encrypt_file(encrypt_input_path, output_path, password, kdf_settings, password_was_generated=password_was_generated)
        
    elif args.decrypt:
        decrypt_file(decrypt_input_path, output_path, verify_path, password, args.force_insecure_decrypt)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)