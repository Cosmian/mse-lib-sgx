"""mse_lib_sgx.sgx.key module."""

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from mse_lib_sgx.error import SGXError


def get_mrenclave_key() -> bytes:
    """Get key tied to the current enclave (MRENCLAVE measurement).

    SGX sealing key is derived with HKDF-SHA256 using a random salt to
    avoid use of the same secret for the same enclave (MRENCLAVE). Store
    the secret to support reboot, see `encrypted files`_ in Gramine.

    Returns
    -------
    bytes
        32 bytes key used to create enclave's public key.

    .. _encrypted files:
        https://gramine.readthedocs.io/en/latest/manifest-syntax.html#encrypted-files

    """
    mr_enclave_key: bytes
    try:
        with open("/dev/attestation/keys/_sgx_mrenclave", "rb") as f:
            mr_enclave_key = f.read(16)
    except FileNotFoundError as exc:
        raise SGXError("Not running inside Intel SGX") from exc

    if len(mr_enclave_key) != 16:
        raise SGXError("EGETKEY instruction failed!")

    salt: bytes = os.urandom(16)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"mse-sgx-enclave-sealing-key",
    )

    return hkdf.derive(mr_enclave_key)
