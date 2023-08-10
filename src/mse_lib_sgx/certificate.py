"""mse_lib_sgx.certificate module."""

import hashlib
import ipaddress
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Union, cast
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)
from intel_sgx_ra.quote import Quote
from intel_sgx_ra.ratls import SGX_QUOTE_EXTENSION_OID, get_quote_from_cert

from mse_lib_sgx.sgx.quote import get_quote


class Certificate:
    """Certificate class.

    Parameters
    ----------
    subject_alternative_name : str
        Value subjectAltName to add in the X509 certificate.
    subject : x509.Name
        Ordered list of Relative Distinguished Names (RDNs).
        See `x509.Name`_.
    root_path : Path
        Path to store certificate and private key.
    expiration_date: datetime
        Expiration date of the certificate.
    ratls : Optional[bytes]
        Bytes to insert in report_data of the SGX quote if RATLS certificate.

    Attributes
    ----------
    cert_path : Path
        Path of the RATLS certificate created.
    key_path : Path
        Path of the private key.
    sk : ec.EllipticCurvePrivateKey
        Private key on SECP256R1.
    expiration_date : datetime
        Expiration date of the certificate.
    cert : x509.Certificate
        X.501 certificate.
    quote : Optional[Quote]
        Intel SGX quote to use for RATLS certificate if any.

    .. _x509.Name:
        https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Name

    """

    def __init__(
        self,
        subject_alternative_name: str,
        subject: x509.Name,
        root_path: Path,
        expiration_date: datetime,
        ratls: Optional[bytes],
    ):
        """Init constructor of SGXCertificate."""
        self.cert_path: Path = root_path / "cert.ratls.pem"
        self.key_path: Path = root_path / "key.ratls.pem"
        self.sk: ec.EllipticCurvePrivateKey = (
            ec.generate_private_key(curve=ec.SECP256R1())
            if not self.key_path.exists()
            else cast(
                ec.EllipticCurvePrivateKey,
                load_pem_private_key(data=self.key_path.read_bytes(), password=None),
            )
        )
        self.expiration_date: datetime = expiration_date
        self.cert: x509.Certificate
        self.quote: Optional[Quote] = None
        if self.key_path.exists() and self.cert_path.exists():
            self.cert = x509.load_pem_x509_certificate(data=self.cert_path.read_bytes())
            if ratls is not None:
                self.quote = get_quote_from_cert(self.cert)
        else:
            custom_extension: Optional[x509.ExtensionType] = None
            if ratls is not None:
                pubkey_hash: bytes = hashlib.sha256(
                    self.sk.public_key().public_bytes(
                        encoding=Encoding.X962,
                        format=PublicFormat.UncompressedPoint,
                    )
                ).digest()
                user_report_data: bytes = (
                    pubkey_hash + ratls if ratls is not None else pubkey_hash
                )
                self.quote = Quote.from_bytes(
                    get_quote(user_report_data=user_report_data)
                )
                custom_extension = x509.UnrecognizedExtension(
                    oid=SGX_QUOTE_EXTENSION_OID, value=bytes(self.quote)
                )
            self.cert = generate_x509(
                subject_alternative_name=subject_alternative_name,
                subject=subject,
                private_key=self.sk,
                expiration_date=self.expiration_date,
                custom_extension=custom_extension,
            )
            self.write(self.cert_path, self.key_path)

    def write(
        self, cert_path: Path, sk_path: Path, encoding: Encoding = Encoding.PEM
    ) -> None:
        """Write X509 certificate and private key to `cert_path` and `sk_path`.

        Parameters
        ----------
        cert_path : Path
            Output path of the X509 certificate.
        sk_path : Path
            Output path of the private key.
        encoding : Encoding
            Encoding used to write X509 certificate.

        """
        cert_path.write_bytes(self.cert.public_bytes(encoding))
        sk_path.write_bytes(
            self.sk.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption(),
            )
        )


def generate_x509(
    subject_alternative_name: str,
    subject: x509.Name,
    private_key: ec.EllipticCurvePrivateKey,
    expiration_date: datetime,
    custom_extension: Optional[x509.ExtensionType] = None,
) -> x509.Certificate:
    """Build a self-signed X509 certificate given parameters.

    Parameters
    ----------
    subject_alternative_name : str
        Value subjectAltName to add in the X509 certificate.
    subject : x509.Name
        Ordered list of Relative Distinguished Names (RDNs).
        See `x509.Name`_.
    private_key : ec.EllipticCurvePrivateKey
        Private key to sign the X509 certificate.
    expiration_date : datetime
        Expiration date of the X509 certificate.
    custom_extension : Optional[x509.ExtensionType]
        Custom X509 v3 extension. Mainly used for RA-TLS certificate.

    Returns
    -------
    x509.Certificate
        Self-signed X509 certificate with input parameters.

    .. _x509.Name:
        https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Name

    """
    issuer: x509.Name = subject  # issuer=subject for self-signed certificate

    san: Union[x509.IPAddress, x509.DNSName]
    try:
        san = x509.IPAddress(ipaddress.ip_address(subject_alternative_name))
    except ValueError:
        san = x509.DNSName(subject_alternative_name)

    builder: x509.CertificateBuilder = x509.CertificateBuilder()

    builder = (
        builder.subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(expiration_date)
        .add_extension(
            x509.SubjectAlternativeName([san]),
            critical=False,
        )
    )

    if custom_extension is not None:
        builder = builder.add_extension(custom_extension, critical=False)

    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )

    return builder.sign(private_key=private_key, algorithm=hashes.SHA256())


def to_wildcard_domain(domain: str) -> str:
    """Transform domain to wildcard domain.

    Parameters
    ----------
    domain : str
        Domain name to transform.

    Returns
    -------
    str
        New domain with first subdomain replaced with wildcard.

    """
    try:
        _ = ipaddress.ip_address(domain)
    except ValueError:
        if "." not in domain:
            return domain

        subdomains: List[str] = urlparse(f"//{domain}").netloc.split(".")

        if len(subdomains) <= 2:
            return domain

        return f"*.{'.'.join(subdomains[1:])}"

    return domain
