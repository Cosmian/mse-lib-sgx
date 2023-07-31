"""mse_lib_sgx.base64url module."""

import base64


def base64url_encode(value: bytes) -> str:
    """Perform URL safe base64 encode on `value` without padding.

    Parameters
    ----------
    value : bytes
        Bytes to encode.

    Returns
    -------
    str
        Result of URL safe base64 encode on `value`.

    """
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def base64url_decode(value: str) -> bytes:
    """Perform URL safe base64 decode on `value` badly padded.

    Parameters
    ----------
    value : str
        String to decode.

    Returns
    -------
    bytes
        Result of URL safe base64 decode on `value`.

    """
    modulus: int = len(value) % 4

    # add padding depending on modulus
    if modulus:
        # 3 -> '='
        # 2 -> '=='
        value += "=" * (4 - modulus)

    return base64.urlsafe_b64decode(value)
