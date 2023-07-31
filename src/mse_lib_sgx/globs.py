"""mse_lib_sgx.globs module."""

import os
import threading
from pathlib import Path
from typing import Optional
from uuid import UUID

from cryptography import x509
from cryptography.x509.oid import NameOID

CODE_SECRET_KEY: Optional[bytes] = None

EXIT_EVENT: threading.Event = threading.Event()

ID: Optional[UUID] = None

SSL_PRIVATE_KEY: Optional[str] = None
NEED_SSL_PRIVATE_KEY: bool = False

HOME_DIR_PATH: Path = Path(os.getenv("HOME", "/root"))
KEY_DIR_PATH: Path = Path(os.getenv("KEY_PATH", "/key"))
SECRETS_PATH: Path = Path(os.getenv("SECRETS_PATH", "/root/.cache/mse/secrets.json"))
SEALED_SECRETS_PATH: Path = Path(
    os.getenv("SEALED_SECRETS_PATH", "/root/.cache/mse/sealed_secrets.json")
)
MODULE_DIR_PATH: Path = Path(os.getenv("MODULE_PATH", "/mse-app"))

CODE_KEY_PATH: Path = KEY_DIR_PATH / "code.key"
ENCLAVE_SK_PATH: Path = KEY_DIR_PATH / "enclave.key"
ENCLAVE_PK_PATH: Path = KEY_DIR_PATH / "enclave.pub"

SUBJECT: x509.Name = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Ile-de-France"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Paris"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cosmian Tech"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ]
)

TIMEOUT: Optional[int] = None
