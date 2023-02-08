"""mse_lib_sgx.sgx_quote module."""

from mse_lib_sgx.error import SGXError

SGX_QUOTE_MAX_SIZE: int = 8192


def get_quote(user_report_data: bytes) -> bytes:
    """Read the quote if inside Intel SGX enclave."""
    if len(user_report_data) > 64:
        raise SGXError("user_report_data must be at most 64 bytes")

    attestation_type: str
    try:
        with open("/dev/attestation/attestation_type", "rb") as f:
            attestation_type = f.read(32).decode("utf-8").strip()

        if attestation_type != "dcap":
            raise SGXError(f"Only DCAP supported, found '{attestation_type}'")

        with open("/dev/attestation/user_report_data", "wb") as f:
            f.write(user_report_data)

        with open("/dev/attestation/quote", "rb") as f:
            return f.read(SGX_QUOTE_MAX_SIZE)
    except FileNotFoundError as exc:
        raise SGXError("Not running inside Intel SGX") from exc
