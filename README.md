# Upload files to S3 from a remote SSH host

This Python script connects to a remote system over SSH (e.g., a Home Assistant OS instance), scans a directory for files with a given extension (e.g., `.tar`), and uploads the files to an S3 bucket, verifying each upload via SHA256 checksums. 

Useful for automating the backup of Home Assistant or other IoT systems to AWS S3.

### Requirements
- Python 3.10+
- an existing S3 bucket
- an AWS identity with permission to:
  - `s3:ListBucket`
  - `s3:GetObject`
  - `s3:PutObject`
- the `sha256sum` utility must be available on the remote SSH host

### Configuration
Create a `.env` file in the root of the project by copying the provided `.env.example`:
```bash
cp .env.example .env
```

Then you must set:
- SSH access details (user, host, port, private key or password)
- Remote source directory and file extension to match
- S3 bucket and destination path
- IAM Roles Anywhere config (optional)

Credentials can be provided in two ways:
- Using the default AWS profile on your local system (e.g., ~/.aws/credentials)
- Using IAM Roles Anywhere, by providing:
  - An X.509 certificate
  - Private key
  - Trust Anchor ARN
  - Profile ARN
  - Role ARN
  - Region

These should all be part of your IAM Roles Anywhere setup.\
If default credentials are not found, the script automatically falls back to IAM Roles Anywhere.

## Usage
```bash
# Better using a virtual environment
pip install -r requirements.txt
python upload_to_s3.py
```

To avoid re-uploading the same files, the script tracks uploaded filenames and their hashes in a local JSON file (e.g., upload_history.lock.json).
If this file is missing, the script compares remote files against what already exists in S3 to reconstruct the state.

### Error handling and notification
- All operational events and errors are logged to the file defined by `LOG_FILENAME` in your .env file.

- If a fatal error occurs (e.g., SSH connection failure, file upload error, SHA256 mismatch), the script logs it and optionally sends a notification to Home Assistant via a webhook.\
To enable notifications:
  1. create an automation as shown in the file [ha_automation.yaml](ha_automation.yaml)
  2. set HA_WEBHOOK_URL in your .env file

### Security Tips
Never commit your .env file to Git.

Use a dedicated IAM Role with minimal S3 permissions for backups.

Prefer SSH key authentication over passwords when possible.

Ensure your .pem and private keys are kept secure and not readable by anyone in the system.

### Tested with:
- AWS S3
- Home Assistant OS
- Linux SSH servers

## TODO
Home Assistant Addon with:
  - notification on successful/failed backup event
  - upload history JSON file signed using PGP

## Contact
For questions or contributions, feel free to open an issue or pull request.