import os
import json
import time
import struct
from pathlib import Path
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib



def compute_file_hash(file_path: Path, master_key: bytes) -> str:
    """Returns the SHA-256 hash of file content + key."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    h.update(master_key)  # Ensures different users produce different hashes
    return h.hexdigest()[:16] + ".enc"




def encrypt_file_with_master_key(input_path: Path, output_path: Path, master_key: bytes):
    assert len(master_key) == 32, "Master key must be 32 bytes (AES-256)"

    # Gather metadata
    stat = input_path.stat()
    metadata = {
        "original_name": input_path.name,
        "original_extension": input_path.suffix,
        "size": stat.st_size,
        "modified": time.ctime(stat.st_mtime)
    }
    metadata_json = json.dumps(metadata).encode()

    aesgcm = AESGCM(master_key)

    # Encrypt metadata
    metadata_nonce = os.urandom(12)  # 12-byte nonce for AES-GCM
    encrypted_metadata = aesgcm.encrypt(metadata_nonce, metadata_json, associated_data=None)

    # Encrypt file content
    with open(input_path, "rb") as f:
        file_data = f.read()
    content_nonce = os.urandom(12)
    encrypted_content = aesgcm.encrypt(content_nonce, file_data, associated_data=None)

    # Compute filename (hash of file content + key)
    random_name = compute_file_hash(input_path, master_key)
    full_output_path = output_path / random_name

    # Write to output file:
    # metadata_nonce (12 bytes)
    # metadata length (4 bytes)
    # encrypted metadata (variable length)
    # content_nonce (12 bytes)
    # encrypted content (variable length)

    length_metadata = len(encrypted_metadata)

    with open(full_output_path, "wb") as f:
        f.write(metadata_nonce)
        f.write(struct.pack(">I", length_metadata))
        f.write(encrypted_metadata)
        f.write(content_nonce)
        f.write(encrypted_content)

    print(f"[+] Encrypted: {input_path} → {full_output_path}")








def decrypt_file_with_master_key(encrypted_path: Path, output_dir: Path, master_key: bytes):
    assert len(master_key) == 32, "Master key must be 32 bytes (AES-256)"

    with open(encrypted_path, "rb") as f:
        data = f.read()

    if len(data) < 16 + 4 + 12:  # minimum length check (nonce + length + nonce)
        raise ValueError(f"Encrypted file {encrypted_path.name} is too short or corrupted.")

    metadata_nonce = data[:12]
    metadata_len = struct.unpack(">I", data[12:16])[0]

    if metadata_len > len(data) - 16 - 12:
        raise ValueError(f"Invalid metadata length in {encrypted_path.name}")

    encrypted_metadata = data[16:16 + metadata_len]
    content_nonce = data[16 + metadata_len:16 + metadata_len + 12]
    encrypted_content = data[16 + metadata_len + 12:]

    aesgcm = AESGCM(master_key)

    # Decrypt metadata
    metadata_json = aesgcm.decrypt(metadata_nonce, encrypted_metadata, associated_data=None)
    metadata = json.loads(metadata_json)

    output_filename = metadata.get("original_name", "recovered_file")
    output_path = output_dir / output_filename

    # Decrypt content
    content = aesgcm.decrypt(content_nonce, encrypted_content, associated_data=None)

    with open(output_path, "wb") as f:
        f.write(content)

    print(f"[+] Decrypted: {encrypted_path.name} → {output_path.name}")