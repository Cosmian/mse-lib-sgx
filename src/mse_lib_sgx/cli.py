"""mse_lib_sgx.cli.bootstrap module."""

import argparse
import asyncio
import importlib
import logging
import shutil
import sys
import sysconfig
import uuid
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path

from cryptography import x509
from hypercorn.asyncio import serve
from hypercorn.config import Config
from mse_lib_crypto.x25519 import x25519_pk_from_sk
from mse_lib_crypto.xsalsa20_poly1305 import decrypt_directory

from mse_lib_sgx import __version__, globs
from mse_lib_sgx.certificate import Certificate
from mse_lib_sgx.copy import copytree
from mse_lib_sgx.error import SecurityError
from mse_lib_sgx.http_server import serve as serve_sgx_secrets
from mse_lib_sgx.sgx.key import get_mrenclave_key


def parse_args() -> argparse.Namespace:
    """Argument parser.

    Returns
    -------
    argparse.Namespace
        Namespace with parsed arguments.

    """
    parser = argparse.ArgumentParser(
        description="Bootstrap ASGI/WSGI Python web application for Gramine"
    )
    parser.add_argument(
        "application",
        type=str,
        help="ASGI application path (as module:app)",
    )

    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="hostname of the server",
    )
    parser.add_argument("--port", type=int, default=443, help="port of the server")
    parser.add_argument(
        "--subject",
        type=str,
        help="Subject as RFC 4514 string for the RA-TLS certificate",
    )
    parser.add_argument(
        "--san", type=str, help="Subject Alternative Name in the RA-TLS certificate"
    )
    parser.add_argument(
        "--app-dir",
        required=True,
        type=Path,
        help="path of the python web application",
    )
    parser.add_argument(
        "--id",
        required=True,
        type=uuid.UUID,
        help="identifier of the application as UUID in RFC 4122",
    )
    parser.add_argument(
        "--plaincode", action="store_true", help="unencrypted python web application"
    )
    parser.add_argument(
        "--timeout", type=int, help="seconds before closing the configuration server"
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--debug", action="store_true", help="debug mode with more logging"
    )

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "--ratls",
        type=int,
        metavar="EXPIRATION_DATE",
        help="generate a self-signed certificate for RA-TLS with a "
        "specific expiration date (Unix time)",
    )

    group.add_argument("--no-ssl", action="store_true", help="use HTTP without SSL")

    group.add_argument(
        "--certificate",
        type=Path,
        metavar="CERTIFICATE_PATH",
        help="custom certificate used for the SSL connection, "
        "private key must be sent through the configuration server",
    )

    return parser.parse_args()


class SslAppMode(Enum):
    """SSL Application Mode."""

    RATLS_CERTIFICATE = 1  # self-signed SGX certificate with quote
    CUSTOM_CERTIFICATE = 2  # provided by the code provider
    NO_SSL = 3  # no SSL, will be done by the SSL proxy


# pylint: disable=too-many-statements,too-many-branches
def run() -> None:
    """Entrypoint of the CLI.

    Note
    ----
    Once all the secrets sent to the configuration server, three options:
    - [--self-signed] If the app owner relies on the enclave certificate,
      then start the app server using this same certificate
    - [--certificate] Start the app server using the certificate
      provided by the app owner. In that case, the certificate
      is already present in the workspace of the program
      but the private key is sent by the app owner
      when the configuration server is up.
    - [--no-ssl] If the app owner and the users trust the operator (cosmian)
      then don't use https connection.

    """
    args: argparse.Namespace = parse_args()

    globs.HOME_DIR_PATH.mkdir(exist_ok=True)
    globs.KEY_DIR_PATH.mkdir(exist_ok=True)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="[%(asctime)s] [%(levelname)s] %(message)s",
    )

    if args.timeout:
        globs.TIMEOUT = args.timeout

    ssl_private_key_path = None
    expiration_date = datetime.now() + timedelta(hours=10)

    ssl_app_mode: SslAppMode
    if args.no_ssl:
        # The conf server use the self-signed cert
        # No ssl for the app server
        ssl_app_mode = SslAppMode.NO_SSL
    elif args.certificate:
        # The conf server use the self-signed cert
        # The app server use the app owner cert
        ssl_app_mode = SslAppMode.CUSTOM_CERTIFICATE
        ssl_private_key_path = globs.KEY_DIR_PATH / "key.pem"
    else:
        # The conf server and the app server will use the same self-signed cert
        ssl_app_mode = SslAppMode.RATLS_CERTIFICATE
        expiration_date = datetime.utcfromtimestamp(args.ratls)

    logging.info("Generating self-signed certificate...")

    enclave_sk: bytes
    enclave_pk: bytes
    if not globs.ENCLAVE_SK_PATH.exists():
        enclave_sk = get_mrenclave_key()
        globs.ENCLAVE_SK_PATH.write_bytes(enclave_sk)
        enclave_pk = x25519_pk_from_sk(globs.ENCLAVE_SK_PATH.read_bytes())

        if len(enclave_pk) != 32:
            raise SecurityError("Bad enclave pk length!")

        globs.ENCLAVE_PK_PATH.write_bytes(enclave_pk)
    else:
        enclave_sk = globs.ENCLAVE_SK_PATH.read_bytes()
        enclave_pk = globs.ENCLAVE_PK_PATH.read_bytes()

        if len(enclave_sk) != 32:
            raise SecurityError("Bad enclave sk length!")

        if x25519_pk_from_sk(enclave_sk) != enclave_pk:
            raise SecurityError("Malformed enclave's keypair!")

    cert: Certificate = Certificate(
        subject_alternative_name=args.san if args.san else "localhost",
        subject=(
            x509.Name.from_rfc4514_string(args.subject)
            if args.subject
            else globs.SUBJECT
        ),
        root_path=globs.KEY_DIR_PATH,
        expiration_date=expiration_date,
        ratls=enclave_pk,
    )

    if not globs.MODULE_DIR_PATH.exists():
        logging.info("Starting the configuration server...")
        serve_sgx_secrets(
            hostname=args.host,
            port=args.port,
            certificate=cert,
            app_id=args.id,
            need_ssl_private_key=ssl_app_mode == SslAppMode.CUSTOM_CERTIFICATE,
            timeout=globs.TIMEOUT,
        )

        if globs.CODE_SECRET_KEY is not None:
            globs.CODE_KEY_PATH.write_bytes(globs.CODE_SECRET_KEY)
            globs.MODULE_DIR_PATH.mkdir()
            decrypt_directory(
                dir_path=args.app_dir,
                key=globs.CODE_KEY_PATH.read_bytes(),
                ext=".enc",
                out_dir_path=globs.MODULE_DIR_PATH,
            )
        else:
            copytree(
                src=args.app_dir, dst=globs.MODULE_DIR_PATH, copy_function=shutil.copy
            )

        if (
            ssl_app_mode == SslAppMode.CUSTOM_CERTIFICATE
            and globs.SSL_PRIVATE_KEY
            and ssl_private_key_path is not None
        ):
            ssl_private_key_path.write_text(globs.SSL_PRIVATE_KEY)

    config_map = {
        "bind": f"{args.host}:{args.port}",
        "alpn_protocols": ["h2"],
        "workers": 1,
        "accesslog": "-",
        "errorlog": "-",
        "worker_class": "uvloop",
        "wsgi_max_body_size": 2 * 1024 * 1024 * 1024,  # 2 GB
    }

    if ssl_app_mode == SslAppMode.CUSTOM_CERTIFICATE:
        config_map["certfile"] = args.certificate
        config_map["keyfile"] = ssl_private_key_path
    elif ssl_app_mode == SslAppMode.RATLS_CERTIFICATE:
        config_map["certfile"] = cert.cert_path
        config_map["keyfile"] = cert.key_path

    config = Config.from_mapping(config_map)

    logging.info("Loading the application...")
    module_name, application_name = args.application.split(":")

    sys.path.append(f"{globs.MODULE_DIR_PATH}")

    logging.debug("MODULE_PATH=%s", globs.MODULE_DIR_PATH)
    logging.debug("sys.path: %s", sys.path)
    logging.debug("sysconfig.get_paths(): %s", sysconfig.get_paths())
    logging.debug("application: %s", args.application)

    application = getattr(importlib.import_module(module_name), application_name)

    logging.info("Starting the application (mode=%s)...", ssl_app_mode.name)
    asyncio.run(serve(application, config))
