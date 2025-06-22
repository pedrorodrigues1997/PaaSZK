# 🔐 PaasZK – Secure Vault Sync CLI

![Project Logo](https://raw.githubusercontent.com/pedrorodrigues1997/PaaSZK/main/logo.png)

**PaasZK** is a lightweight, CLI-based encrypted vault system that lets you safely store and sync confidential files across cloud providers. It supports encrypted file storage, cloud synchronization, and backend storage abstraction — all under your control.

---

## 🔒 Purpose

PaasZK was built to:

- **Encrypt your sensitive files** locally using strong AES encryption.
- **Store and synchronize** encrypted files across multiple cloud storage providers (S3, Dropbox, Google Drive).
- Allow **easy configuration** of storage backends using a secure YAML config file.


---

## 🛡️ Encryption Details

- **Algorithm**: AES-256 GCM (Galois/Counter Mode)
- **Key Derivation**: From passphrase using your master key loading mechanism.
- **Config & metadata** are stored in an encrypted YAML file using AES-GCM with random IV and authentication tag.

AES-GCM provides **authenticated encryption**, meaning it protects both the **confidentiality** and **integrity** of your data.

---

## ⚙️ Basic Usage

```bash
# Initialize a new vault in the current directory
paaszk init [--import-key PATH]
##Sets up the current directory as a new encrypted vault.

## --import-key PATH: Optional path to an existing encrypted derived master key to import instead of generating a new one.

# Encrypt and push encrypted files to remote storage
paaszk push [FILE_OR_FOLDER] [--storage STORAGE_NAME] [--recursive]
##Encrypt and upload files to your configured storage.

##Defaults to current directory if no file/folder specified.

##--storage STORAGE_NAME: Specify which storage backend to use.

##--recursive: If pushing a directory, recursively include all subfiles.


# Pull remote encrypted files into vault
paaszk pull --storage STORAGE_NAME
##Download and decrypt all files from the specified storage backend into your local cache.

# Configure storages
paaszk config <command> [options]
#Available subcommands:

 #   list: List all configured storage backends.

paaszk config list [--yaml]

  #  --yaml: Output the raw YAML config.


#add: Add a new storage backend.

paaszk config add NAME

 #   NAME: The name to assign the new storage backend.

#remove: Remove an existing storage backend.

paaszk config remove NAME

 #   NAME: The storage backend to remove

----------------------------------------------------
#Initialize a vault and import an existing key:

paaszk init --import-key ./my_derived_key.enc

#Push all files from current folder recursively to Dropbox backend:

paaszk push . --storage dropbox --recursive

#Pull all files from the Google Drive backend:

paaszk pull --storage google_drive

#Add a new S3 storage backend called my_s3:

paaszk config add my_s3

#List all storage backends in YAML format:

paaszk config list --yaml
 