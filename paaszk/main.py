import os
import argparse
import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from collections import defaultdict
import subprocess
import sys
import json
import struct
from pathlib import Path

from paaszk.dropbox_backend import pull_from_dropbox, push_to_dropbox
from paaszk.s3_backend import push_to_s3, pull_from_s3
from paaszk.googledrive_backend import push_to_google_drive, pull_from_google_drive
from paaszk.crypto import (
    encrypt_master_key,
    decrypt_master_key,
    save_encrypted_master_key,
    load_master_key,
    VAULT_KEY_FILENAME,
    HIDDEN_VAULT_DIR
)
from paaszk.file_ops import (
    encrypt_file_with_master_key,
    decrypt_file_with_master_key
)

from paaszk.config import (
    add_storage_backend,
    get_storage_config,
    remove_backend,
    list_backends,
    create_default_config_file,
    CACHE_DIR)





EXCLUDED_DIRS = {".vault_cache", ".paaszksafe"}

def should_exclude(path: Path) -> bool:
    # Exclude hidden vault folders and files inside them
    for part in path.parts:
        if part in EXCLUDED_DIRS:
            return True
    return False






def init_vault(vault_path: Path, import_key_file: Path | None = None):
    vault = vault_path.resolve()
    vault_safe_path = vault / HIDDEN_VAULT_DIR

    passphrase = getpass.getpass("Enter vault passphrase: ")


    if not vault.exists():
        print(f"Creating vault directory at: {vault}")
        vault.mkdir(parents=True)
    else:
        print(f"Vault directory already exists: {vault}")

    key_file = vault_safe_path / VAULT_KEY_FILENAME
    if key_file.exists():
        print("Vault already initialized. Aborting.")
        return

    if import_key_file:
        # Read the encrypted derived key from file
        encrypted_blob = import_key_file.read_bytes()
        # Decrypt it using the user passphrase
        try:
            master_key = decrypt_master_key(encrypted_blob, passphrase)
        except Exception as e:
            print(f"Failed to decrypt provided key file: {e}")
            return
    else:
        master_key = os.urandom(32)  # 256-bit random MK
        #print(f"Master key (base64): {base64.b64encode(master_key).decode()}")
        

    try:
        encrypted_blob = encrypt_master_key(master_key, passphrase)
        save_encrypted_master_key(vault, encrypted_blob)
        print("[+] Encrypted master key saved.")
        
        if import_key_file and import_key_file.exists():
            import_key_file.unlink()
            print("[i] Temporary import key file deleted.")

        create_default_config_file(vault_safe_path, passphrase)
        print("[+] Default config file created.")
    except Exception as e:
        print(f"[!] Failed to finalize vault setup: {e}")
        return


    cache_path = vault_path / CACHE_DIR
    cache_path.mkdir(exist_ok=True)

    # Make hidden on Windows
    if sys.platform == "win32":
        subprocess.run(["attrib", "+h", str(cache_path)], shell=True)


    print(f"Vault initialized successfully at {vault}")




def handle_pull(storage_name:str):
    print("[i] Pulling encrypted files from remote storage...")
    vault = Path.cwd()
    output_dir = vault
    cache_path = vault / CACHE_DIR
    cache_path.mkdir(exist_ok = True)


    try:
        master_key = load_master_key(vault)
        storage_type, storage_conf = get_storage_config(storage_name, master_key)
    except Exception as e:
        print(f"[!] Failed to load storage config or master key: {e}")
        return
    
    print("Downloading all encrypted fiels from remote storage...")
    # Dispatch based on storage type
    if storage_type == "s3":
        pull_from_s3(storage_conf, cache_path)
    elif storage_type == "dropbox":
        pull_from_dropbox(storage_conf, cache_path)
    elif storage_type == "google_drive":
        pull_from_google_drive(storage_conf, cache_path)
    elif storage_type == "local":
        print("Files will be fectehd from .vault_cache")
          

    else:
        print(f"[!] Unsupported storage type: {storage_type}")
        return

    print(f"[+] Pulled files into cache. Processing...")
     # Step 2: Pick only latest version per original file
    files_by_name = defaultdict(list)

    for enc_path in cache_path.glob("*.enc"):
        try:
            with open(enc_path, "rb") as f:
                data = f.read()

            # AES-GCM nonce is 12 bytes, not 16
            metadata_nonce = data[:12]

            # Next 4 bytes is metadata length
            metadata_len = struct.unpack(">I", data[12:16])[0]

            # Metadata ciphertext + tag
            encrypted_metadata = data[16:16 + metadata_len]

            aesgcm = AESGCM(master_key)
            metadata_json = aesgcm.decrypt(metadata_nonce, encrypted_metadata, None)
            metadata = json.loads(metadata_json)

            original_name = metadata.get("original_name")
            modified_time = metadata.get("modified")
        

            if original_name:
                files_by_name[original_name].append((enc_path, modified_time))

        except Exception as e:
            print(f"[!] Skipping corrupted file {enc_path.name}: {e}")

            
    # Step 3: Pick newest version and decrypt
    for original_name, versions in files_by_name.items():
        # Sort by 'created' timestamp
        latest_file = sorted(versions, key=lambda x: x[1], reverse=True)[0][0]
        decrypt_file_with_master_key(latest_file, output_dir, master_key)



     # Step 4: Clean up cache
    for enc_file in cache_path.glob("*.enc"):
        try:
            enc_file.unlink()
        except Exception as e:
            print(f"[!] Failed to delete {enc_file.name}: {e}")

        print(f"[+] Decrypted latest versions of files into: {output_dir}")








def handle_push(file_path: Path, recursive: bool, storage_name: str):
    vault_path = Path.cwd()
    cache_path = vault_path / CACHE_DIR
    cache_path.mkdir(exist_ok=True)
    
    try:
        master_key = load_master_key(vault_path)
        storage_type, storage_conf = get_storage_config(storage_name, master_key)
    except Exception as e:
        print(f"[!] Could not load master key or storage config: {e}")
        return

    file_path = file_path.resolve()
    encrypted_files = []
    if file_path.is_dir():
        if not recursive:
            print(f"'{file_path}' is a directory. Use --recursive to encrypt its contents.")
            return
        print(f"[i] Encrypting files in directory: {file_path}")
        for item in file_path.rglob("*") if recursive else file_path.iterdir():
            if item.is_file() and not should_exclude(item):
                encrypt_file_with_master_key(item, cache_path, master_key)
                encrypted_files.append(item)
            else:
                print(f"[!] Skipped: {item}")
    elif file_path.is_file():
        print(f"[i] Encrypting file: {file_path}")
        encrypt_file_with_master_key(file_path, cache_path, master_key)
        encrypted_files.append(item)
    else:
        print(f"[!] Invalid path: {file_path}")
        return

    print(f"[+] Encryption complete. Uploading to '{storage_name}' ({storage_type})...")

    if storage_type == "s3":
        push_to_s3(storage_conf, cache_path)
    elif storage_type == "dropbox":
        push_to_dropbox(storage_conf, cache_path)
    elif storage_type == "google_drive":
        push_to_google_drive(storage_conf, cache_path)
    elif storage_type == "local":
        print("[i] Using local backend — deleting original plaintext files...")
        for f in encrypted_files:
            try:
                f.unlink()
                print(f"[+] Deleted: {f}")
            except Exception as e:
                print(f"[!] Failed to delete {f}: {e}")   

    else:
        print(f"[!] Unsupported storage type: {storage_type}")
        return
     





def main():
    parser = argparse.ArgumentParser(description="Vault CLI Tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Init command
    init_parser = subparsers.add_parser("init", help="Initialize the current directory as a vault")
    init_parser.add_argument("--import-key",type=Path,help="Path to the encrypted derived master key file to import instead of generating a new key")

    # Push command
    push_parser = subparsers.add_parser("push", help="Encrypt and upload a file to storage")
    push_parser.add_argument("file", nargs="?", default=".", help="Path to file or folder to push (defaults to current directory)")
    push_parser.add_argument("--storage", help="Storage provider to use")
    push_parser.add_argument("--recursive", action="store_true", help="Recursively push directory contents")

    # Pull command
    pull_parser = subparsers.add_parser("pull", help="Decrypt all files from the cache")
    pull_parser.add_argument("--storage", required=True, help="Storage backend name to pull from")

    # Config command
    config_parser = subparsers.add_parser("config", help="Manage storage configuration")
    config_sub = config_parser.add_subparsers(dest="config_command", required=True)

    # List configured storage
    list_parser = config_sub.add_parser("list", help="List configured storage backends")
    list_parser.add_argument("--yaml", action="store_true", help="Print config in raw YAML format")

    # Validate credentials (optional)
    config_sub.add_parser("validate", help="Validate configured storage credentials")

    # Add new storage backend
    add_parser = config_sub.add_parser("add", help="Add a new storage backend")
    add_parser.add_argument("name", help="Name of the new storage provider")

    # Remove storage backend
    remove_parser = config_sub.add_parser("remove", help="Remove a storage backend")
    remove_parser.add_argument("name", help="Name of the storage provider to remove")






    args = parser.parse_args()

    current_dir = Path.cwd()

    if args.command == "init":
        init_vault(current_dir, import_key_file=args.import_key)

    elif args.command == "push":
        handle_push(Path(args.file), args.recursive, args.storage)

    elif args.command == "pull":
        # Use --storage to determine where to pull from
        storage_name = args.storage
        handle_pull(storage_name)

    elif args.command == "config":
        try:
            master_key = load_master_key(current_dir)
            if args.config_command == "list":
                list_backends(master_key, as_yaml=args.yaml)
            elif args.config_command == "remove":
                remove_backend(args.name, master_key)
                print(f"[+] Storage config '{args.name}' removed.")
            elif args.config_command == "add":
                add_storage_backend(args.name, master_key)
                print(f"[+] Added storage backend: {args.name}")
        except Exception as e:
            print(f"[!] Config operation failed: {e}")

     

    

if __name__ == "__main__":
    main()
