import dropbox
import os
from pathlib import Path
from dropbox.exceptions import ApiError, AuthError
from dropbox.files import WriteMode, FileMetadata


def push_to_dropbox(config: dict, cache_path: Path):
    token = config.get("access_token")
    remote_path = config.get("remote_path", "/PaasZK")

    if not token:
        print("[!] Dropbox access token missing in config.")
        return

    try:
        dbx = dropbox.Dropbox(token)
        dbx.users_get_current_account()
    except AuthError as e:
        print(f"[!] Dropbox authentication failed: {e}")
        return

    print("[Dropbox] Starting upload of encrypted files...")

    for file_path in cache_path.glob("*.enc"):
        if not file_path.is_file():
            continue

        dest_path = f"{remote_path}/{file_path.name}"
        try:
            with open(file_path, "rb") as f:
                print(f"[Dropbox] Uploading {file_path.name} -> {dest_path}")
                dbx.files_upload(f.read(), dest_path, mode=WriteMode("overwrite"))
        except Exception as e:
            print(f"[!] Failed to upload {file_path.name}: {e}")

    print("[+] Upload to Dropbox complete.")


def pull_from_dropbox(config: dict, cache_path: Path):
    token = config.get("access_token")
    remote_path = config.get("remote_path", "/PaasZK")

    if not token:
        print("[!] Dropbox access token missing in config.")
        return

    try:
        dbx = dropbox.Dropbox(token)
        dbx.users_get_current_account()
    except AuthError as e:
        print(f"[!] Dropbox authentication failed: {e}")
        return

    print("[Dropbox] Fetching file list from remote folder...")

    try:
        entries = dbx.files_list_folder(remote_path).entries
    except ApiError as e:
        print(f"[!] Dropbox API error: {e}")
        return

    cache_path.mkdir(parents=True, exist_ok=True)

    for entry in entries:
        if isinstance(entry, FileMetadata):
            local_path = cache_path / entry.name
            print(f"[Dropbox] Downloading {entry.name} -> {local_path}")

            try:
                metadata, res = dbx.files_download(entry.path_lower)
                with open(local_path, "wb") as f:
                    f.write(res.content)
                print(f"[+] Downloaded {entry.name}")
            except Exception as e:
                print(f"[!] Failed to download {entry.name}: {e}")

    print("[+] Pull from Dropbox complete.")