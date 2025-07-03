# Upload files to S3 from a remote SSH host

This Python script connects to a remote system over SSH (e.g., a Home Assistant OS instance), scans a directory for files with a given extension (e.g., `.tar`), and uploads the files to an S3 bucket, verifying each upload via SHA256 checksums. 

Useful for automating the backup of Home Assistant or other IoT systems to AWS S3.

### Requirements
- Python 3.10+
- An existing S3 bucket
- An AWS identity with permission to:
  - `s3:ListBucket`
  - `s3:GetObject`
  - `s3:PutObject`
- The `sha256sum` utility must be available on the remote SSH host

### Configuration
Create a `.env` file in the root of the project by copying the provided `.env.example`:
```bash
cp .env.example .env
```

Then you must set:
- SSH access details (user, host, port, private key or password)
- Remote source directory and file extension to match
- S3 bucket and destination path
- AWS credentials or IAM Roles Anywhere config

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

The script will:
1. Connect to the remote SSH host

2. List all matching files in the specified directory

3. Compute SHA256 checksums for each file

4. Check which files haven't been uploaded to S3 yet

5. Download missing files via SCP

6. Upload them to S3

7. Verify the uploaded file matches the original checksum

8. Update a local JSON-based upload history

### Upload history
To avoid re-uploading the same files, the script tracks uploaded filenames and their hashes in a local JSON file (e.g., upload_history.lock.json).
If this file is missing, the script compares remote files against what already exists in S3 to reconstruct the state.

### Logging
Logs are written to the file specified by LOG_FILENAME in the .env file.

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