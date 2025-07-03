#!/usr/bin/env python3
"""
Automates the secure transfer of backup files from a remote SSH-accessible device
(e.g., Home Assistant OS) to an Amazon S3 bucket, ensuring integrity via SHA256 checksums.

Although originally intended for Home Assistant backups, it is designed to work with
any remote system reachable via SSH and any file extension.
Environment variables defined in a `.env` file are used for configuration.

The script supports:
    - password and key-based for SSH authentication
    - AWS authentication via default credentials or IAM Roles Anywhere.

It then:
1. Connect via SSH to the Home Assistant OS add-on
2. List files in the remote directory and calculate SHA256 of each one
3. Read the local upload history JSON file if any
4a. If existing, check if any HA filename is not in the JSON. If so:
    - upload missing files to S3 using default AWS profile or
    temporary IAM Roles Anywhere credentials
    - verify that S3 files' SHA256 matches the remote HA files's SHA256 for integrity check
    - raise an error even if a single comparison fails
    Otherwise (all remote filenames are already listed in the JSON file) do nothing
4b. If not existing, check if S3 contains files. If not, upload all remote files.
    If not empty, check for missing files that need to be uploaded. Upload them and then
    re-create upload history file.
"""

import hashlib
import json
import logging
import os
import shutil
import sys
import tempfile
from collections import Counter
from typing import cast

import boto3
import botocore
import botocore.exceptions
import paramiko
from dotenv import load_dotenv
from iam_rolesanywhere_session import IAMRolesAnywhereSession
from scp import SCPClient, SCPException

# Load .env variables
load_dotenv()

##########################################################################
# Settings section

# SSH AUTH
if not (SSH_USER := os.getenv("SSH_USER")):
    raise ValueError("No 'SSH_USER' set in .env file")

if not (SSH_HOST := os.getenv("SSH_HOST")):
    raise ValueError("No 'SSH_HOST' set in .env file")

if not (SSH_PORT_STR := os.getenv("SSH_PORT")):
    raise ValueError("No 'SSH_PORT' set in .env file")

if SSH_PORT_STR.isdigit():
    SSH_PORT = int(SSH_PORT_STR)
else:
    raise ValueError("Invalid 'SSH_PORT' set in .env file")

SSH_PASS = os.getenv("SSH_PASS") or None

SSH_KEY_PATH = os.getenv("SSH_KEY_PATH") or None

if SSH_PASS and SSH_KEY_PATH:
    raise ValueError("Cannot have both 'SSH_PASS' and 'SSH_KEY_PATH'")

# S3
if not (S3_BUCKET_NAME := os.getenv("S3_BUCKET_NAME")):
    raise ValueError("No 'S3_BUCKET_NAME' set in .env file")

if not (S3_DIR := os.getenv("S3_BUCKET_NAME")):
    raise ValueError("No 'S3_DIR' set in .env file")

# FILES

if not (BACKUP_FILES_EXT := os.getenv("BACKUP_FILES_EXT")):
    raise ValueError("No 'BACKUP_FILES_EXT' set in .env file")

if not (SOURCE_DIR := os.getenv("SOURCE_DIR")):
    raise ValueError("No 'SOURCE_DIR' set in .env file")

REMOTE_DIR = f"/{SOURCE_DIR}/*{BACKUP_FILES_EXT}"

LOCAL_DIR = os.path.join(os.path.dirname(__file__))

if not (LOG_FILENAME := os.getenv("LOG_FILENAME")):
    raise ValueError("No 'LOG_FILENAME' set in .env file")

if not (UPLOAD_HISTORY_FILENAME := os.getenv("UPLOAD_HISTORY_FILENAME")):
    raise ValueError("No 'UPLOAD_HISTORY_FILENAME' set in .env file")

UPLOAD_HISTORY_FILE_PATH = os.path.join(LOCAL_DIR, UPLOAD_HISTORY_FILENAME)
##########################################################################

# Logger configuration
logging.basicConfig(
    filename=os.path.join(LOCAL_DIR, LOG_FILENAME),
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


def get_files_to_upload(
    remote_files: dict[str, str], upload_history: dict[str, str]
) -> dict[str, str]:
    """
    Identify remote files that have not yet been uploaded to S3.

    This function compares the base filenames of the given remote files against
    the list of already uploaded files recorded in the upload history. It returns
    only the files that are new and need to be uploaded.

    Args:
        - remote_files (dict[str, str]): a mapping of remote file paths to their
        corresponding SHA256 checksums
        - upload_history (dict[str, str]): a mapping of previously uploaded S3 keys
        to their checksums

    Returns:
        dict[str, str]: a subset of remote_files that have not yet been uploaded
    """
    files_to_upload: dict[str, str] = {}

    # Extract the set of filenames that already exist in upload history
    uploaded_filenames = [
        os.path.basename(s3_key)
        for s3_key in upload_history.keys()
        if s3_key.startswith(S3_DIR)
    ]

    # Find remote files whose base name is not in the uploaded list
    for remote_path, remote_sha in remote_files.items():
        filename = os.path.basename(remote_path)
        if filename not in uploaded_filenames:
            files_to_upload[remote_path] = remote_sha

    if not files_to_upload:
        logging.info("All remote files have already been uploaded to S3, nothing do")
        sys.exit()

    logging.info("Found files to upload: %s", files_to_upload)
    return files_to_upload


def update_or_create_upload_history_file(file_content: dict[str, str]) -> None:
    """
    Overwrite or create the upload history file with the provided content.

    This function writes the given dictionary to the upload history file path
    in JSON format. After the operation completes, it exits the program.

    Args:
        file_content (dict[str, str]): a dictionary mapping S3 keys to their
        corresponding SHA256 checksums, representing the latest upload history.
    """
    with open(UPLOAD_HISTORY_FILE_PATH, "w", encoding="utf-8") as f:
        json.dump(file_content, f, indent=2)
        logging.info("Written upload history file to disk")
    sys.exit()


class SSHManager:
    """
    Handles SSH-based interactions with a remote host.

    This class uses Paramiko to establish an SSH connection to a remote server and
    provides methods to list remote files, calculate their SHA256 digests,
    download them locally via SCP, and validate hash integrity.

    Attributes:
        ssh_client (paramiko.SSHClient): the SSH client used for all remote operations

    Methods:
        - connect: establish and return a new SSH connection using Paramiko
        - download_remote_files: download a file from the remote host to the
        local filesystem using SCP
        - validate_sha256: raise an error if the given digest length is not valid for SHA256
        - calc_sha256: calculate SHA256 checksums for a list of remote file paths
        - list_remote_files: list files in the configured remote directory and return
        a mapping of remote paths to their SHA256 digests
    """

    def __init__(self) -> None:
        """Initialize the paramiko SSH client that will be used along the session."""
        self.ssh_client = self.connect()

    def connect(self) -> paramiko.SSHClient:
        """
        Establish an SSH connection using Paramiko.

        Returns:
            paramiko.SSHClient: a connected SSH client instance.
        """

        try:
            client = paramiko.SSHClient()

            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            client.connect(
                SSH_HOST,
                password=SSH_PASS,
                port=SSH_PORT,
                username=SSH_USER,
                key_filename=SSH_KEY_PATH,
                timeout=10,
            )
            return client
        except paramiko.AuthenticationException as e:
            logging.error("Error while connecting to SSH host: %s", str(e))
            raise e

    def download_remote_files(
        self, remote_file_path: str, local_file_path: str
    ) -> None:
        """
        Download a remote file over SCP and save it locally.

        Args:
            remote_file_path (str): full path to the remote file
            local_file_path (str): path where the file will be saved locally
        """

        transport = self.ssh_client.get_transport()
        if transport is None:
            raise RuntimeError(
                "SSH transport is not available (SSH connection might be closed)"
            )

        with SCPClient(transport) as scp:
            try:
                scp.get(remote_file_path, local_file_path, preserve_times=True)
                logging.info("Downloaded remote file on: '%s'", local_file_path)
            except SCPException as exc:
                logging.error(
                    "SCP protocol error for %s: %s", remote_file_path, str(exc)
                )

    def validate_sha256(self, sha256_digest: int) -> None:
        """
        Validate that the SHA256 digest has the correct length (64 characters).

        Args:
            digest (str): SHA256 checksum string to validate

        Raises:
            ValueError: if the digest is not 64 characters long
        """
        invalid_digest_error_msg = "Invalid SHA-256 length returned by host"
        if sha256_digest != 64:
            logging.error(invalid_digest_error_msg)
            raise ValueError(invalid_digest_error_msg)

    def calc_sha256(self, paths: list[str]) -> dict[str, str]:
        """
        Compute SHA256 checksums for a list of files on the remote host.

        Args:
            paths (list[str]): list of remote file paths to hash

        Returns:
            dict[str, str]: mapping of file path to SHA256 hash

        Raises:
            If it cannot calculate the SHA256 of any file in paths argument
        """

        digest_dict: dict[str, str] = {}

        for file in paths:
            cmd = f"sha256sum {file}"

            _, stdout, stderr = self.ssh_client.exec_command(cmd)

            err = stderr.read().decode().strip()
            remote_sha256sum_error_msg = f"Remote sha256sum error: {err}"
            if err:
                logging.error(remote_sha256sum_error_msg)
                raise RuntimeError(remote_sha256sum_error_msg)

            output = stdout.read().decode().strip().split()

            digest, path = output

            self.validate_sha256(len(digest))

            digest_dict[path] = digest.lower()

        logging.info("Calculated and validated SHA256 of remote files: %s", digest_dict)
        return digest_dict

    def list_remote_files(self) -> dict[str, str]:
        """
        List files in the configured remote directory and return their SHA256 digests.

        Returns:
            dict[str, str]: mapping of remote file paths to their SHA256 checksums
        """

        cmd = f"ls {REMOTE_DIR}"

        _, stdout, stderr = self.ssh_client.exec_command(cmd)

        err = stderr.read().decode().strip()

        remote_error_msg = f"Error while listing remote files: {err}"
        if err:
            logging.error(remote_error_msg)
            raise RuntimeError(remote_error_msg)

        files = stdout.read().decode().strip().splitlines()

        no_remote_files_error_msg = "Cannot find any remote files"
        if not files:
            logging.warning(no_remote_files_error_msg)

        logging.info("Found remote files: %s", files)
        return self.calc_sha256(files)


class AWSManager:
    """
    Manages interactions with AWS services, specifically S3.

    This class supports default AWS credentials and fallback to IAM Roles Anywhere
    if credentials are not found. It includes utilities for listing S3 files,
    verifying file integrity via SHA256 and uploading files to S3.

    Attributes:
        s3_client (boto3.client): authenticated S3 client used for all operations.

    Methods:
        - aws_auth: attempt to authenticate with default AWS credentials. If unavailable,
        fallback to IAM Roles Anywhere authentication
        - list_s3_files: retrieve a list of filenames from the configured S3 directory prefix
        - verify_sha256: verify that the SHA256 checksum of a file stored in S3 matches the
        expected checksum of a remote file
        - upload_to_s3: download files from a remote system, upload them to S3, verify their
        integrity, and update the upload history
    """

    def __init__(self) -> None:
        """Initialize AWSManager and authenticate the S3 client."""
        self.s3_client = self.aws_auth()

    def _get_iam_role_credentials_from_env(self) -> dict[str, str]:
        """
        Load IAM Roles Anywhere credentials from environment variables.

        Returns:
            dict[str, str]: dictionary containing all required credential fields.
        """
        logging.warning(
            "Default credentials not found, falling back to IAM Roles Anywhere auth"
        )

        creds = {
            "cert_path": os.getenv("CERTIFICATE_PATH"),
            "prv_key_path": os.getenv("PRIVATE_KEY_PATH"),
            "trust_anchor_arn": os.getenv("AWS_TRUST_ANCHOR_ARN"),
            "profile_arn": os.getenv("AWS_PROFILE_ARN"),
            "role_arn": os.getenv("AWS_ROLE_ARN"),
            "region": os.getenv("AWS_REGION"),
        }

        if not all(creds.values()):
            logging.error(
                "Missing one or more IAM Roles Anywhere env variables: %s",
                [k for k, v in creds.items() if not v],
            )
            sys.exit()

        # Safe to cast: all values checked as non-None above
        return cast(dict[str, str], creds)

    def _iam_role_anywhere_auth(self) -> boto3.client:
        """
        Authenticate S3 client using IAM Roles Anywhere.

        Returns:
            boto3.client: authenticated boto3 client for S3.
        """
        aws_creds = self._get_iam_role_credentials_from_env()

        try:
            roles_anywhere_session = IAMRolesAnywhereSession(
                profile_arn=aws_creds["profile_arn"],
                role_arn=aws_creds["role_arn"],
                trust_anchor_arn=aws_creds["trust_anchor_arn"],
                certificate=aws_creds["cert_path"],
                private_key=aws_creds["prv_key_path"],
                region=aws_creds["region"],
            ).get_session()
        except FileNotFoundError as e:
            logging.error("Certificate or private key file not found: %s", e)
            raise
        except botocore.exceptions.ClientError as e:
            logging.error("AWS client error during IAM Roles Anywhere auth: %s", e)
            raise
        return roles_anywhere_session.client("s3")

    def aws_auth(self) -> boto3.client:
        """
        Authenticate with AWS using default credentials or fallback to IAM Roles Anywhere.

        Returns:
            boto3.client: authenticated S3 client.
        """
        client: boto3.client

        try:
            session = boto3.Session()

            session.client("sts").get_caller_identity()

            client = session.client("s3")
        except botocore.exceptions.NoCredentialsError:
            client = self._iam_role_anywhere_auth()

        return client

    def list_s3_files(self) -> list[str] | None:
        """
        List files in the configured S3 bucket and prefix (non-paginated).

        Returns:
            list[str] | None: list of file names in the S3 directory,
            or None if empty or not found.
        """
        try:
            response = self.s3_client.list_objects_v2(
                Bucket=S3_BUCKET_NAME, Prefix=f"{S3_DIR}/"
            )

            try:
                contents = response["Contents"]
            except KeyError:
                logging.info(
                    "S3 directory: %s/%s nonexistent or empty", S3_BUCKET_NAME, S3_DIR
                )
                return None

            keys = [
                os.path.basename(obj["Key"])
                for obj in contents
                if obj["Key"].endswith(BACKUP_FILES_EXT)
            ]

            logging.info("Found existing files in S3: %s", keys)
            return keys

        except botocore.exceptions.ClientError as exc:
            logging.error("Error listing S3 files: %s", exc)
            raise

    def verify_sha256(self, s3_file_path: str, sha_to_compare: str) -> None:
        """
        Verify that the SHA256 hash of an S3 file matches the expected value.

        Args:
            s3_file_path (str): S3 object key.
            sha_to_compare (str): expected SHA256 checksum.

        Raises:
            SystemError: If the hash does not match.
        """
        # Retrieve the object from the S3 bucket
        obj = self.s3_client.get_object(Bucket=S3_BUCKET_NAME, Key=s3_file_path)

        # Initialize the SHA256 hasher
        hasher = hashlib.sha256()

        # Get the object's binary stream body
        body = obj["Body"]

        # Stream the file in chunks and update the hash progressively
        for chunk in body.iter_chunks():
            hasher.update(chunk)

        # Compute the final SHA256 hex digest
        s3_file_sha = hasher.hexdigest()

        # Compare the computed hash with the expected one of the remote file
        if s3_file_sha != sha_to_compare:
            remote_path = os.path.dirname(REMOTE_DIR) + os.path.basename(s3_file_path)
            download_error_msg = (
                f"{s3_file_path}:{s3_file_sha} != {remote_path}:{sha_to_compare}"
            )
            logging.error(download_error_msg)
            raise SystemError

        logging.info("Upload verified for file: %s", s3_file_path)

    def upload_to_s3(
        self,
        files_to_upload_to_s3: dict[str, str],
        ssh_manager_obj: SSHManager,
        upload_history_file: dict[str, str] | None = None,
    ) -> None:
        """
        Upload files to S3 after downloading from a remote machine and verify integrity.

        Args:
            - files_to_upload_to_s3 (dict[str, str]): mapping of remote file path
            to SHA256 checksum
            - ssh_manager_obj (SSHManager): SSH manager used to retrieve remote files
            - upload_history_file (dict[str, str] | None): optional existing upload
            history file to update
        """

        # Create a local temp directory
        tmpdir = tempfile.mkdtemp(prefix="ha_home_bkp_")

        if not upload_history_file:
            upload_history_file = {}

        for remote_path, remote_sha in files_to_upload_to_s3.items():
            fname = os.path.basename(remote_path)
            local_path = os.path.join(tmpdir, fname)
            s3_key = f"{S3_DIR}/{fname}"

            # Download file from remote
            ssh_manager_obj.download_remote_files(remote_path, local_path)

            # From local temp, upload it to S3
            try:
                self.s3_client.upload_file(local_path, S3_BUCKET_NAME, s3_key)
            except botocore.exceptions.ClientError as exc:
                logging.error("Error uploading: %s", str(exc))
                raise

            logging.info("Uploaded to s3://%s/%s", S3_BUCKET_NAME, s3_key)

            # Once uploaded, ensure the remote file's SHA256 hash matches
            # the SHA256 hash of the file in S3
            self.verify_sha256(s3_key, remote_sha)

            # Update upload history file content
            upload_history_file[s3_key] = remote_sha

        shutil.rmtree(tmpdir)  # wipe temp files

        # Update/Create history file
        update_or_create_upload_history_file(upload_history_file)


if __name__ == "__main__":
    # Init SSH Manager class
    ssh_manager = SSHManager()

    # List remote files
    remote_files_details = ssh_manager.list_remote_files()

    # Init SSH Manager class
    aws_manager = AWSManager()

    # If upload history file does not exist
    # we have first run case or upload history file got deleted
    if not os.path.exists(UPLOAD_HISTORY_FILE_PATH):
        # Check if there are files on S3
        # If so:
        if s3_files_list := aws_manager.list_s3_files():
            # Create a list of remote filenames
            remote_files_list = [
                os.path.basename(fn) for fn in list(remote_files_details.keys())
            ]

            # Nothing to do, 2 lists are identical
            if Counter(s3_files_list) == Counter(remote_files_list):
                logging.info("Same files both on source and destination")

                # Re-create upload history file
                upload_history_file_content = {
                    f"{S3_DIR}/{fname}": remote_files_details[
                        f"{os.path.dirname(REMOTE_DIR)}/{fname}"
                    ]
                    for fname in s3_files_list
                }

                logging.info("Re-created local upload history file")
                update_or_create_upload_history_file(upload_history_file_content)

            # Lists are not the same
            # So get only the files on remote SSH host that are NOT in S3 files list
            else:
                missing = {
                    path: sha
                    for path, sha in remote_files_details.items()
                    if os.path.basename(path) not in s3_files_list
                }

                # Re-create upload history file
                upload_history_file_content = {
                    f"{S3_DIR}/{os.path.basename(fn)}": sha
                    for fn, sha in remote_files_details.items()
                }

                aws_manager.upload_to_s3(
                    missing, ssh_manager, upload_history_file_content
                )

        # No S3 files found case:
        # download all files from SSH device on a temp directory
        # and then upload to S3
        aws_manager.upload_to_s3(remote_files_details, ssh_manager)

    # Case where upload history file exists locally
    # Read upload history file content
    with open(UPLOAD_HISTORY_FILE_PATH, "r", encoding="utf-8") as upload_file_r:
        upload_history_file_content = json.load(upload_file_r)

    # Get a dictionary of the files to upload
    missing_files_on_s3 = get_files_to_upload(
        remote_files_details, upload_history_file_content
    )

    # Download missing files from SSH device on a temp directory
    # and then upload to S3
    aws_manager.upload_to_s3(
        missing_files_on_s3, ssh_manager, upload_history_file_content
    )
