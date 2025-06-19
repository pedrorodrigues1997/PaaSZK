
from pathlib import Path
from minio import Minio
from minio.error import S3Error

def push_to_s3(storage_conf: dict, cache_path: Path):
    endpoint_url = storage_conf.get("endpoint_url", "")
    access_key = storage_conf["aws_access_key_id"]
    secret_key = storage_conf["aws_secret_access_key"]
    bucket_name = storage_conf["bucket"]
    region = storage_conf.get("region", "us-west-002")

    if endpoint_url.startswith("https://"):
        endpoint = endpoint_url[len("https://"):]
        secure = True
    elif endpoint_url.startswith("http://"):
        endpoint = endpoint_url[len("http://"):]
        secure = False
    else:
        endpoint = endpoint_url
        secure = True  # default to secure

    client = Minio(
        endpoint,
        access_key=access_key,
        secret_key=secret_key,
        secure=secure,
        region=region,
    )

    print(f"[+] Uploading encrypted files in '{cache_path}' to bucket '{bucket_name}'...")

    for enc_file in cache_path.glob("*.enc"):
        key = enc_file.name

        try:
            client.fput_object(
                bucket_name=bucket_name,
                object_name=key,
                file_path=str(enc_file)
            )
            enc_file.unlink()
            print(f"[+] Uploaded and deleted: {enc_file.name}")
        except S3Error as err:
            print(f"[!] Failed to upload {enc_file.name}: {err}")




def pull_from_s3(storage_conf: dict, cache_path: Path):
    """
    Downloads all .enc files from S3-compatible storage to cache_path.
    """

    endpoint_url = storage_conf.get("endpoint_url")
    access_key = storage_conf.get("aws_access_key_id")
    secret_key = storage_conf.get("aws_secret_access_key")
    bucket = storage_conf.get("bucket")

    if not all([endpoint_url, access_key, secret_key, bucket]):
        print("[!] Missing required S3 configuration fields.")
        return

    # Parse endpoint and determine secure or not
    if endpoint_url.startswith("https://"):
        endpoint = endpoint_url[len("https://"):]
        secure = True
    elif endpoint_url.startswith("http://"):
        endpoint = endpoint_url[len("http://"):]
        secure = False
    else:
        endpoint = endpoint_url
        secure = True  # default to secure

    client = Minio(
        endpoint,
        access_key=access_key,
        secret_key=secret_key,
        secure=secure,
    )

    try:
        # Check bucket exists
        if not client.bucket_exists(bucket):
            print(f"[!] Bucket '{bucket}' does not exist.")
            return

        print(f"[+] Listing objects in bucket '{bucket}'...")
        objects = client.list_objects(bucket, recursive=True)

        for obj in objects:
            if obj.object_name.endswith(".enc"):
                dest_path = cache_path / Path(obj.object_name).name
                print(f"[+] Downloading {obj.object_name} to {dest_path}")
                client.fget_object(bucket, obj.object_name, str(dest_path))

    except S3Error as err:
        print(f"[!] S3 error during pull: {err}")

    print("[+] Finished downloading files from S3.")