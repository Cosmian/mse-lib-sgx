"""mse_lib_sgx.error module."""


class CryptoError(Exception):
    """Internal cryptographic error."""


class UserError(Exception):
    """User error in the code of the enclave."""


class InternalError(Exception):
    """Internal generic error."""


class SGXError(Exception):
    """Error related to SGX."""


class SecurityError(Exception):
    """Potential security issue."""


class InteruptError(Exception):
    """Interrupt HTTP server."""
