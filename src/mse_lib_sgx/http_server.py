"""mse_lib_sgx.http_server module."""

import json
import logging
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional
from uuid import UUID

from mse_lib_crypto.seal_box import unseal

from mse_lib_sgx import globs
from mse_lib_sgx.base64url import base64url_decode
from mse_lib_sgx.certificate import Certificate
from mse_lib_sgx.error import CryptoError


class SGXHTTPRequestHandler(BaseHTTPRequestHandler):
    """HTTP server to configure the targeted WSGI/ASGI application.

    Server is killed if it receives correcly the following elements
    on POST method:
        - uuid
        - (optional) ssl_private_key
        - (optional) app_secrets
        - (optional) app_sealed_secrets
        - (optional if plain code) code_secret_key

    Note
    ----
    Contains only one endpoint '/' with GET and POST methods.

    """

    def do_GET(self) -> None:
        """GET /."""
        msg: bytes = b"Waiting for code secret key and/or ssl private key..."
        self.send_response(200)
        self.send_header("Content-Length", str(len(msg)))
        # We send an extra header to easily know when the configuration server is up
        self.send_header("Mse-Status", "Waiting")
        self.end_headers()
        self.wfile.write(msg)

    def do_POST(self) -> None:
        """POST /."""
        logging.info("Processing POST query...")
        content_length: int = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        # body is a JSON with keys:
        # - uuid
        # - (optional) ssl_private_key
        # - (optional) app_secrets
        # - (optional) app_sealed_secrets
        # - (optional if plain code)  code_secret_key
        try:
            data = json.loads(body.decode("utf8"))

            if app_secrets := data.get("app_secrets"):
                globs.SECRETS_PATH.parent.mkdir(parents=True, exist_ok=True)
                globs.SECRETS_PATH.write_bytes(json.dumps(app_secrets).encode("utf-8"))

            if app_sealed_secrets := data.get("app_sealed_secrets"):
                content: Dict[str, Any] = json.loads(
                    unseal(
                        base64url_decode(app_sealed_secrets),
                        globs.ENCLAVE_SK_PATH.read_bytes(),
                    )
                )
                if "code_secret_key" in content:
                    globs.CODE_SECRET_KEY = bytes.fromhex(content["code_secret_key"])

                    if len(globs.CODE_SECRET_KEY) != 32:
                        raise CryptoError("Incorrect key length!")
                globs.SEALED_SECRETS_PATH.parent.mkdir(parents=True, exist_ok=True)
                globs.SEALED_SECRETS_PATH.write_bytes(
                    json.dumps(content).encode("utf-8")
                )

            # Do not process queries which have not the `uuid` data field
            # Probably a robot
            if UUID(data["uuid"]) != globs.ID:
                self.send_response_only(401)
                self.end_headers()
                return

            if globs.NEED_SSL_PRIVATE_KEY:
                globs.SSL_PRIVATE_KEY = data["ssl_private_key"]

            if "code_secret_key" in data:
                globs.CODE_SECRET_KEY = bytes.fromhex(data["code_secret_key"])

                if len(globs.CODE_SECRET_KEY) != 32:
                    raise CryptoError("Incorrect key length!")
        # might be: KeyError, ValueError, json.JSONDecodeError, CryptoError
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logging.error(exc)
            self.send_response_only(401)
            self.end_headers()
            return

        self.send_response_only(200)
        self.end_headers()
        globs.EXIT_EVENT.set()


def serve(
    hostname: str,
    port: int,
    certificate: Certificate,
    app_id: UUID,
    need_ssl_private_key: bool,
    timeout: Optional[int],
):
    """Serve SGXHTTPRequestHandler and run kill event in another thead.

    Server is killed if it receives correctly:
        - uuid
        - (optional) ssl_private_key
        - (optional) app_secrets
        - (optional) app_sealed_secrets
        - (optional if plain code) code_secret_key
    or after `timeout`.

    Parameters
    ----------
    hostname : str
        Hostname of the server.
    port : int
        Port of the server.
    certificate : Certificate
        Certificate used for SSL.
    app_id : UUID
        Unique identifier of the server.
    need_ssl_private_key : bool
        Whether you provide a custom private key through
        configuration server.
    timeout : Optional[int]
        Duration in ms before closing the HTTP server.

    """
    globs.NEED_SSL_PRIVATE_KEY = need_ssl_private_key
    globs.ID = app_id

    httpd = HTTPServer((hostname, port), SGXHTTPRequestHandler)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(
        certfile=str(certificate.cert_path.resolve()),
        keyfile=str(certificate.key_path.resolve()),
    )

    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    if timeout is not None:
        timer = threading.Timer(interval=timeout, function=kill)
        timer.start()

        threading.Thread(target=kill_event, args=(httpd, timer)).start()
    else:
        threading.Thread(target=kill_event, args=(httpd, None)).start()

    httpd.serve_forever()


def kill_event(httpd: HTTPServer, timer: Optional[threading.Timer]):
    """Event to kill `httpd`.

    Loop exits if `globs.EXIT_EVENT` is set or timer thread finished.

    Parameters
    ----------
    httpd : HTTPServer
        Server to be killed.
    timer : Optional[threading.Timer]
        Timer thread to kill `httpd` if provided.

    """
    while True:
        if globs.EXIT_EVENT.is_set():
            logging.info("Stopping the configuration server...")

            if timer:
                timer.cancel()

            httpd.shutdown()
            return

        time.sleep(1)


def kill():
    """Set `globs.EXIT_EVENT` to kill HTTPServer with `kill_event`."""
    globs.EXIT_EVENT.set()
