import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type
import subprocess
import sys
import getpass
import hashlib
VAULT_KEY_FILENAME = ".vault_key.enc"
HIDDEN_VAULT_DIR = ".paaszksafe"

# Argon2 parameters - tune as needed for security/performance
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 64 * 1024  # 64 MB
ARGON2_PARALLELISM = 2
ARGON2_HASH_LEN = 32
ARGON2_TYPE = Type.ID




def load_master_key(vault_path: Path, passphrase: str = None) -> bytes:
    vault_safe_path = vault_path / HIDDEN_VAULT_DIR
    key_file = vault_safe_path / VAULT_KEY_FILENAME
    if not key_file.exists():
        raise FileNotFoundError("Vault is not initialized or key file missing.")

    encrypted_blob = key_file.read_bytes()

    if not passphrase:
        passphrase = getpass.getpass("Enter vault passphrase: ")

    return decrypt_master_key(encrypted_blob, passphrase)

def encrypt_shared_key_for_user(shared_key: bytes, passphrase: str) -> bytes:
    """Encrypt a derived shared key using a passphrase with Argon2id and AES-GCM."""
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(passphrase, salt)  # <-- uses Argon2id

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, shared_key, None)

    return salt + nonce + ciphertext  # bundle all together for decoding

def derive_shared_key_argon2(master_key: bytes, user_id: str) -> bytes:
    """
    Derive a 256-bit shared key from master_key and user_id using Argon2id.
    - master_key: bytes-like object (32 bytes).
    - user_id: Unique identifier for the user (used as salt).
    """
    salt = hashlib.sha256(user_id.encode()).digest()[:16]  # 16-byte salt
    return hash_secret_raw(
        secret=master_key,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=ARGON2_TYPE,
    )

def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from passphrase and salt using Argon2id."""
    return hash_secret_raw(
        secret=passphrase.encode(),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=ARGON2_TYPE,
    )

def encrypt_master_key(master_key: bytes, passphrase: str) -> bytes:
    """Encrypt the master key with passphrase-derived key, return blob to save."""
    salt = os.urandom(16)  # 128-bit salt for Argon2
    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # AES-GCM standard nonce size
    ct = aesgcm.encrypt(nonce, master_key, None)  # no additional data
    # Store salt + nonce + ciphertext together for decryption
    return salt + nonce + ct

def decrypt_master_key(encrypted_blob: bytes, passphrase: str) -> bytes:
    """Decrypt the master key from blob using passphrase."""
    salt = encrypted_blob[:16]
    nonce = encrypted_blob[16:28]
    ct = encrypted_blob[28:]
    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

def save_encrypted_master_key(vault_path: Path, encrypted_key: bytes):
    hidden_dir = vault_path / HIDDEN_VAULT_DIR
    hidden_dir.mkdir(exist_ok=True)

    # Make hidden on Windows
    if sys.platform == "win32":
        subprocess.run(["attrib", "+h", str(hidden_dir)], shell=True)

    key_file = hidden_dir / VAULT_KEY_FILENAME
    with open(key_file, "wb") as f:
        f.write(encrypted_key)
    os.chmod(key_file, 0o600)

def load_encrypted_master_key(vault_path: Path) -> bytes:
    key_file = vault_path / VAULT_KEY_FILENAME
    with open(key_file, "rb") as f:
        return f.read()

