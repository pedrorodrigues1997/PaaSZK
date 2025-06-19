import os
import io
from pathlib import Path
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from google.auth.transport.requests import Request

SCOPES = ['https://www.googleapis.com/auth/drive.file']

def authenticate(storage_conf):
    try:
        token_path = Path(storage_conf.get('token_path', Path.cwd() / '.paaszksafe' / 'google_token.json'))
        credentials_path = Path(storage_conf.get('credentials_path', Path.cwd() / '.paaszksafe' / 'credentials.json'))

        print(f"[Google Drive] Loading token from: {token_path} (exists={token_path.exists()})")
        creds = None

        if token_path.exists():
            creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                print("[Google Drive] Refreshing expired token...")
                creds.refresh(Request())
            else:
                print("[Google Drive] Starting OAuth flow...")
                flow = InstalledAppFlow.from_client_secrets_file(str(credentials_path), SCOPES)
                creds = flow.run_local_server(port=0)

            token_path.parent.mkdir(parents=True, exist_ok=True)
            with open(token_path, 'w') as token_file:
                token_file.write(creds.to_json())

        return creds

    except Exception as e:
        print(f"[!] Authentication failed: {e}")
        raise

def get_drive_service(storage_conf):
    try:
        creds = authenticate(storage_conf)
        return build('drive', 'v3', credentials=creds)
    except Exception as e:
        print(f"[!] Failed to initialize Google Drive service: {e}")
        raise

def get_or_create_folder(service, storage_conf):
    folder_name = storage_conf.get('folder_name', 'PaasZK')
    try:
        results = service.files().list(
            q=f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false",
            spaces='drive',
            fields='files(id, name)',
            pageSize=1
        ).execute()

        files = results.get('files', [])
        if files:
            return files[0]['id']

        print(f"[Google Drive] Creating folder: {folder_name}")
        metadata = {'name': folder_name, 'mimeType': 'application/vnd.google-apps.folder'}
        folder = service.files().create(body=metadata, fields='id').execute()
        return folder.get('id')

    except Exception as e:
        print(f"[!] Failed to get or create folder '{folder_name}': {e}")
        raise

def push_to_google_drive(storage_conf, base_path: Path):
    try:
        service = get_drive_service(storage_conf)
        folder_id = get_or_create_folder(service, storage_conf)

        print("[Google Drive] Starting upload of encrypted files...")
        for file_path in base_path.rglob('*.enc'):
            if file_path.is_file():
                rel_path = file_path.relative_to(base_path)
                file_metadata = {
                    'name': str(rel_path).replace('\\', '_'),
                    'parents': [folder_id]
                }
                media = MediaFileUpload(str(file_path), mimetype='application/octet-stream')

                print(f"[Google Drive] Uploading {file_path.name} -> /{storage_conf.get('folder_name', 'PaasZK')}/{file_metadata['name']}")
                try:
                    service.files().create(body=file_metadata, media_body=media).execute()
                except Exception as e:
                    print(f"[!] Failed to upload {file_path.name}: {e}")
        print("[+] Upload to Google Drive complete.")

    except Exception as e:
        print(f"[!] Upload process failed: {e}")

def pull_from_google_drive(storage_conf, base_path: Path):
    try:
        service = get_drive_service(storage_conf)
        folder_id = get_or_create_folder(service, storage_conf)

        print("[Google Drive] Retrieving file list...")
        results = service.files().list(
            q=f"'{folder_id}' in parents and trashed=false",
            fields='files(id, name)',
            pageSize=1000
        ).execute()

        files = results.get('files', [])
        if not files:
            print("[Google Drive] No files found in remote folder.")
            return

        base_path.mkdir(parents=True, exist_ok=True)

        for file in files:
            file_name = file['name']
            file_id = file['id']
            local_file_path = base_path / file_name.replace('_', os.sep)
            local_file_path.parent.mkdir(parents=True, exist_ok=True)

            print(f"[Google Drive] Downloading {file_name} -> {local_file_path}")
            request = service.files().get_media(fileId=file_id)

            try:
                with io.FileIO(local_file_path, 'wb') as fh:
                    downloader = MediaIoBaseDownload(fh, request)
                    done = False
                    while not done:
                        status, done = downloader.next_chunk()
                print(f"[+] Downloaded {file_name}")
            except Exception as e:
                print(f"[!] Failed to download {file_name}: {e}")

        print("[+] Pull from Google Drive complete.")

    except Exception as e:
        print(f"[!] Pull process failed: {e}")