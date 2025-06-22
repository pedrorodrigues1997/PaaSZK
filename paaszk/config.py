from pathlib import Path
import yaml
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import struct
from paaszk.crypto import (
    HIDDEN_VAULT_DIR,
    load_master_key
)

CACHE_DIR = ".vault_cache"
VAULT_CONFIG_FILENAME = "vault_config.yaml"
DEFAULT_CONFIG = {
    "storages": {}
}

def get_config_file_path(vault_path: Path) -> Path:
    return vault_path / HIDDEN_VAULT_DIR / "vault_config.yaml"


def create_default_config_file(vault_safe_path: Path, passphrase :str):
    config_path = vault_safe_path / VAULT_CONFIG_FILENAME
    if config_path.exists():
        print("Config file already exists. Skipping creation.")
        return
    
    yaml_data = yaml.dump(DEFAULT_CONFIG).encode()
    master_key = load_master_key(Path.cwd(), passphrase)

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(master_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(yaml_data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(config_path, "wb") as f:
        f.write(iv)
        f.write(struct.pack(">I", len(encrypted_data)))
        f.write(encrypted_data)

    os.chmod(config_path, 0o600)
    print(f"Default vault config created at {config_path}")

def load_config(master_key: bytes):
    config_file = get_config_file_path(Path.cwd())
    if config_file.exists():
        with open(config_file, "rb") as f:
            data = f.read()
        iv = data[:16]
        length = struct.unpack(">I", data[16:20])[0]
        encrypted_data = data[20:20+length]

        cipher = Cipher(algorithms.AES(master_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        unpadder = padding.PKCS7(128).unpadder()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        yaml_bytes = unpadder.update(padded_data) + unpadder.finalize()

        return yaml.safe_load(yaml_bytes) or {}

    return {}

def save_config(config: dict, master_key: bytes):
    config_file = get_config_file_path(Path.cwd())
    yaml_data = yaml.dump(config).encode()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(master_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(yaml_data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(config_file, "wb") as f:
        f.write(iv)
        f.write(struct.pack(">I", len(encrypted_data)))
        f.write(encrypted_data)

        
def get_storage_config(storage_name: str, master_key: bytes) -> tuple[str, dict]:
    """
    Returns (storage_type, storage_config_dict) for a given storage name.

    Raises KeyError if storage_name not found.
    """
    config = load_config(master_key)
    storages = config.get("storages", {})
    if storage_name not in storages:
        raise KeyError(f"Storage '{storage_name}' not found in config.")
    storage_conf = storages[storage_name]
    storage_type = storage_conf.get("type")
    if not storage_type:
        raise KeyError(f"Storage '{storage_name}' config missing 'type' field.")
    return storage_type, storage_conf        




def add_storage_backend(name: str, master_key: bytes):
    config = load_config(master_key)



    print(f"\n--- Add a new storage backend: {name} ---")
    print("Select storage type:")
    print("1. S3-compatible (e.g. AWS S3, Backblaze B2)")
    print("2. Dropbox")
    print("3. Google Drive")
    print("4. Local Folder")

    choice = input("Enter choice number: ").strip()

    if choice == "1":
        storage_type = "s3"
        access_key = input("AWS Access Key ID: ").strip()
        secret_key = input("AWS Secret Access Key: ").strip()
        region = input("Region (e.g. us-west-000): ").strip()
        bucket = input("Bucket Name: ").strip()
        endpoint = input("Endpoint URL (e.g. https://s3.us-west-000.backblazeb2.com): ").strip()

        new_storage_conf = {
            "type": storage_type,
            "aws_access_key_id": access_key,
            "aws_secret_access_key": secret_key,
            "region": region,
            "bucket": bucket,
            "endpoint_url": endpoint,
        }


    elif choice == "2":
        storage_type = "dropbox"
        access_token = input("Dropbox Access Token: ").strip()
        folder_path = input("Dropbox folder path (e.g. /Apps/MyApp): ").strip()

        new_storage_conf = {
            "type": storage_type,
            "access_token": access_token,
            "folder_path": folder_path,
        }

    elif choice == "3":
        storage_type = "google_drive"
        credentials_path = input("Path to Google OAuth credentials JSON (Advice, rename to credentials.json and place it in .paaszksafe folder): ").strip()
        token_path = input("Path to save/read Google OAuth token (e.g., ~/.paaszk/google_token.json will be default): ").strip()
        folder_name = input("Folder name to write and read from Google drive: ").strip()
        
        if not token_path:
            token_path = None

        if not credentials_path:
            credentials_path = None

        new_storage_conf = {
            "type": storage_type,
            "folder_name" : folder_name,
        }
        if token_path:
            new_storage_conf["token_path"] = token_path

        if credentials_path:
            new_storage_conf["credentials_path"] = credentials_path   

    elif choice == "4":
        storage_type = "local"
        folder_path = input("Enter full path to the local folder (e.g., /home/user/backups or C:\\\\Users\\\\User\\\\Backups): ").strip()

        new_storage_conf = {
            "type": storage_type,
            "folder_path": folder_path,
        }
         

    else:
        print("Invalid choice, aborting.")
        return

    if "storages" not in config:
        config["storages"] = {}

    config["storages"][name] = new_storage_conf

    save_config(config, master_key)
    print(f"\nStorage backend '{name}' of type '{storage_type}' added successfully.")




def remove_backend(name: str, master_key: bytes):
    config = load_config(master_key)
    if name not in config.get("storages", {}):
        print(f"Storage backend '{name}' not found.")
        return
    del config["storages"][name]
    save_config(config, master_key)
    print(f"Removed storage backend '{name}'.")


def list_backends(master_key: bytes, as_yaml=False):
    config = load_config(master_key)
    storages = config.get("storages", {})

    if not storages:
        print("No storage backends configured.")
        return

    if as_yaml:
        print(yaml.dump({"Storages": storages}, sort_keys=False))
    else:
        print("Configured storage backends:")
        for name, data in storages.items():
            storage_type = data.get("type", "unknown")
            print(f"  - {name} (type: {storage_type})")

