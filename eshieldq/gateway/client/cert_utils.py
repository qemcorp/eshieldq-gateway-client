#!/usr/bin/python3
import os
import random
import ssl
import string
import subprocess
import tempfile
from typing import cast
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    PrivateKeyTypes,
)
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.base import Certificate, CertificateSigningRequest
from cryptography.x509.oid import ExtensionOID, NameOID


class CertUtils:
    @staticmethod
    def write_pkcs12_bundle(
        cert_file: str,
        key_file: str,
        out_file: str,
        ca_cert_files: list[str] | None = None,
        friendly_name: str | None = None,
        password: str | bytes | None = None,
        compatibility_mode: bool = False,
    ) -> str:
        password_bytes: bytes | None
        if isinstance(password, str):
            password_bytes = password.encode("utf-8")
        elif password is not None:
            password_bytes = bytes(password)
        else:
            password_bytes = password

        if compatibility_mode:
            if not password_bytes:
                raise ValueError(
                    "compatibility_mode requires a non-empty password for PKCS#12 export"
                )

            # hwdsl2/Libreswan NSS still rejects or hangs on cryptography-generated
            # AES-256/SHA-256 PKCS#12 bundles, so keep the OpenSSL export path for
            # this compatibility mode until NSS accepts the Python-native output.
            passout_file = tempfile.NamedTemporaryFile(delete=False)
            try:
                passout_file.write(password_bytes)
                passout_file.close()
                os.chmod(passout_file.name, 0o600)

                subprocess.run(
                    [
                        "openssl",
                        "pkcs12",
                        "-export",
                        "-inkey",
                        key_file,
                        "-in",
                        cert_file,
                        "-out",
                        out_file,
                        "-passout",
                        f"file:{passout_file.name}",
                        "-keypbe",
                        "AES-256-CBC",
                        "-certpbe",
                        "AES-256-CBC",
                        "-macalg",
                        "SHA256",
                        "-iter",
                        "50000",
                        "-maciter",
                    ]
                    + (["-name", friendly_name] if friendly_name else [])
                    + [
                        item
                        for ca_cert_file in (ca_cert_files or [])
                        for item in ("-certfile", ca_cert_file)
                    ],
                    check=True,
                    capture_output=True,
                )
            finally:
                if os.path.exists(passout_file.name):
                    os.remove(passout_file.name)

            return out_file

        with open(cert_file, "rb") as fd:
            cert = x509.load_pem_x509_certificate(fd.read())

        with open(key_file, "rb") as fd:
            key = serialization.load_pem_private_key(fd.read(), password=None)

        ca_certs = None
        if ca_cert_files:
            ca_certs = []
            for ca_cert_file in ca_cert_files:
                with open(ca_cert_file, "rb") as fd:
                    ca_certs.append(x509.load_pem_x509_certificate(fd.read()))

        encryption = (
            serialization.BestAvailableEncryption(password_bytes)
            if password_bytes
            else serialization.NoEncryption()
        )

        pkcs12_data = pkcs12.serialize_key_and_certificates(
            name=friendly_name.encode("utf-8") if friendly_name else None,
            key=cast(pkcs12.PKCS12PrivateKeyTypes, key),
            cert=cert,
            cas=ca_certs,
            encryption_algorithm=encryption,
        )

        with open(out_file, "wb") as fd:
            fd.write(pkcs12_data)

        return out_file

    @staticmethod
    def get_server_cert(address: str, port: int = 443, timeout=5) -> Certificate:
        cert_str = ssl.get_server_certificate((address, port), timeout=timeout)
        return CertUtils.cert_from_data(cert_str.encode("utf-8"))

    @staticmethod
    def get_server_cert_issuer(address: str) -> str:
        cert = CertUtils.get_server_cert(address=address)
        return cert.issuer.rfc4514_string()

    @staticmethod
    def get_server_common_name(address: str) -> str:
        cert = CertUtils.get_server_cert(address=address)
        return str(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)

    @staticmethod
    def get_server_subject_alt_name(address: str) -> str | None:
        cert = CertUtils.get_server_cert(address=address)

        # verify the Subject Alternative Name extension has the hostname
        # try:
        #     san_extension = cert.extensions.get_extension_for_class(
        #         x509.SubjectAlternativeName
        #     )
        # except x509.ExtensionNotFound:
        #     print("No Subject Alternative Name extension found")
        #     return ""

        # return the subject alternative name extension properties
        # return str(san_extension.value)

        try:
            san = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            san_value = cast(x509.SubjectAlternativeName, san.value)
            return san_value.get_values_for_type(x509.DNSName)[0]
        except x509.ExtensionNotFound:
            return None

    @staticmethod
    def gen_ca_cert(
        alg: str,
        rsa_key_size: int = 4096,
        days: int = 10,
        key_out_file="key.pem",
        cert_out_file="cert.pem",
        ec_curve_name=ec.SECP384R1(),
        subject: x509.Name | None = None,
    ) -> tuple[Certificate, PrivateKeyTypes]:

        # generate a new Key
        if "rsa" in alg.lower():
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=rsa_key_size,
            )
        elif "ec" in alg.lower():
            key = ec.generate_private_key(
                curve=ec_curve_name,
            )  # type: ignore
        else:
            raise ValueError("Unsupported algorithm must be rsa or ecdsa")

        # Write our key to disk for safe keeping
        with open(key_out_file, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        if subject is None:
            subject = issuer = x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, "San X"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OrganizationX"),
                    x509.NameAttribute(NameOID.COMMON_NAME, "Test CA "),
                ]
            )
        else:
            issuer = subject

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(
                # Our certificate will be valid for 10 days
                datetime.now(timezone.utc)
                + timedelta(days=int(days))
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            # RFC 5280 / strict X.509 verification requires a CA certificate to
            # carry a KeyUsage extension asserting keyCertSign (and crlSign).
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            # A Subject Key Identifier is required for RFC 5280 / strict X.509
            # verification so issued certs can reference this CA via their
            # Authority Key Identifier.
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )  # Sign our certificate with our private key
            .sign(key, hashes.SHA384())
        )
        # Write our certificate out to disk.
        with open(cert_out_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        return cert, key

    @staticmethod
    def csr_from_bytes(data: bytes) -> CertificateSigningRequest:
        return x509.load_pem_x509_csr(data)

    @staticmethod
    def sign_csr(
        ca_cert_file: str,
        ca_key_file: str,
        csr_cert: CertificateSigningRequest,
    ) -> Certificate:
        # Sign the CSR using the CA key/cert
        with open(ca_cert_file, "rb") as fd:
            ca_cert_raw = fd.read()
        ca_cert = x509.load_pem_x509_certificate(ca_cert_raw)

        with open(ca_key_file, "rb") as fd:
            ca_key_raw = fd.read()
        ca_key = serialization.load_pem_private_key(data=ca_key_raw, password=None)

        return CertUtils.sign_certificate_request(csr_cert, ca_cert, ca_key)  # type: ignore

    @staticmethod
    def tmp_cert_file(cert: Certificate, out_dir="/tmp/") -> str:
        cert_file = tempfile.NamedTemporaryFile(
            prefix="test_user_cert_", suffix=".pem", dir=out_dir
        ).name

        # write the PEM encoded Cert to file
        with open(cert_file, "wb") as fd:
            fd.write(cert.public_bytes(serialization.Encoding.PEM))

        return cert_file

    @staticmethod
    def gen_user_cert_py(
        ca_cert_file,
        ca_key_file,
        alg="rsa",
        out_dir="/tmp/",
        common_name=None,
        dns_name=None,
    ) -> tuple[str, str]:

        key_file = tempfile.NamedTemporaryFile(
            prefix="test_user_key_", suffix=".pem", dir=out_dir
        ).name

        if "rsa" in alg.lower():
            # generate a new RSA Key
            private_key = CertUtils.gen_rsa_key(key_file)
        else:
            private_key = CertUtils.gen_ec_key(key_file)
        assert os.path.isfile(key_file)

        # make a new CSR (signing request)
        csr_file = tempfile.NamedTemporaryFile(
            prefix="test_csr_", suffix=".csr", dir=out_dir
        ).name

        csr_cert = CertUtils.generate_csr(
            csr_file, private_key, common_name=common_name, dns_name=dns_name
        )
        assert os.path.isfile(csr_file)

        # Sign the CSR using the CA key/cert
        cert = CertUtils.sign_csr(ca_cert_file, ca_key_file, csr_cert)

        cert_file = CertUtils.tmp_cert_file(cert, out_dir=out_dir)

        return cert_file, key_file

    @staticmethod
    def sign_certificate_request(
        csr_cert: CertificateSigningRequest,
        ca_cert: Certificate,
        private_ca_key: CertificateIssuerPrivateKeyTypes,
        validity=365,
    ) -> Certificate:

        builder = (
            x509.CertificateBuilder()
            .subject_name(csr_cert.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr_cert.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(
                # Our certificate will be valid for 10 days
                datetime.now(timezone.utc)
                + timedelta(days=validity)
                # Sign our certificate with our private key
            )
        )
        csr_ext_oids = set()
        for ext in csr_cert.extensions:
            builder = builder.add_extension(ext.value, ext._critical)
            csr_ext_oids.add(ext.oid)

        # Strict X.509 verification (RFC 5280, and OpenSSL/Python ssl strict
        # mode) requires the leaf to carry its own Subject Key Identifier and an
        # Authority Key Identifier matching the issuing CA. CSRs typically omit
        # both, so add them here (without duplicating any already in the CSR).
        if ExtensionOID.SUBJECT_KEY_IDENTIFIER not in csr_ext_oids:
            builder = builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(csr_cert.public_key()),
                critical=False,
            )
        if ExtensionOID.AUTHORITY_KEY_IDENTIFIER not in csr_ext_oids:
            try:
                ca_ski = ca_cert.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                ).value
                aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    ca_ski
                )
            except x509.ExtensionNotFound:
                aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    ca_cert.public_key()
                )
            builder = builder.add_extension(aki, critical=False)

        cert = builder.sign(private_ca_key, hashes.SHA384())

        # return the signed certificate
        return cert

    @staticmethod
    def _sn_to_elliptic_curve(curve_name: str) -> ec.EllipticCurve:
        try:
            curve = getattr(ec, curve_name.upper())
            return curve()
        except AttributeError:
            raise ValueError(f"Invalid curve name: {curve_name}")

    @staticmethod
    def gen_ec_key(key_file, curve_name="secp384r1"):
        key = ec.generate_private_key(
            curve=CertUtils._sn_to_elliptic_curve(curve_name),
        )

        # Write our key to disk for safe keeping
        if key_file:
            with open(key_file, "wb") as f:
                f.write(
                    key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )
        return key

    @staticmethod
    def gen_rsa_key(key_file, key_size=4096):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

        # Write our key to disk for safe keeping
        if key_file:
            with open(key_file, "wb") as f:
                f.write(
                    key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )
            os.chmod(key_file, 0o600)  # Set proper permissions

        return key

    @staticmethod
    def get_alg_name(key: PrivateKeyTypes) -> str:
        if isinstance(key, rsa.RSAPrivateKey):
            return "rsa"
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            return "ec"
        else:
            raise ValueError(f"Unsupported key type {type(key)}")

    @staticmethod
    def generate_csr(
        csr_file, key: CertificateIssuerPrivateKeyTypes, common_name=None, dns_name=None
    ) -> CertificateSigningRequest:

        # generate unique name for certificate
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        if common_name is None:
            common_name = CertUtils.get_alg_name(key) + "-"
            rand_str = "".join(random.choice(string.ascii_letters) for _ in range(8))
            common_name += timestamp + "-" + rand_str + ".strongswan.com"

        if dns_name is None:
            dns_name = timestamp + "strongswan.com"

        # Generate a CSR
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        # Provide various details about who we are.
                        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                        x509.NameAttribute(
                            NameOID.STATE_OR_PROVINCE_NAME, "California"
                        ),
                        x509.NameAttribute(NameOID.LOCALITY_NAME, "San X"),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OrganizationX"),
                        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                    ]
                )
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        # Describe what sites we want this certificate for.
                        x509.DNSName(dns_name),
                    ]
                ),
                critical=False,
                # Sign the CSR with our private key.
            )
            .sign(key, hashes.SHA384())
        )
        if csr_file:
            # Write our CSR out to disk.
            with open(csr_file, "wb") as f:
                f.write(csr.public_bytes(serialization.Encoding.PEM))

        return csr

    @staticmethod
    def cert_from_data(data: bytes) -> Certificate:
        return x509.load_pem_x509_certificate(data)

    @staticmethod
    def get_cert_from_file(cert_file: str) -> Certificate:
        with open(cert_file, "rb") as fd:
            data = fd.read()
        cert = x509.load_pem_x509_certificate(data)
        return cert

    @staticmethod
    def get_cert_id_from_file(cert_file: str) -> str:
        cert = CertUtils.get_cert_from_file(cert_file)
        # get  cert filename from the ID:
        return CertUtils.get_cert_id(cert)

    @staticmethod
    def get_issuer_from_file(cert_file: str) -> str:
        cert = CertUtils.get_cert_from_file(cert_file)
        return cert.issuer.rfc4514_string()

    @staticmethod
    def get_cert_id(cert: Certificate) -> str:
        # get  cert Subject Name from the ID:
        return cert.subject.rfc4514_string()

    @staticmethod
    def gen_test_ca(
        alg="rsa", common_name: str | None = None, out_dir="/tmp/", valid_days=10
    ) -> tuple[str, str]:
        cert_file = tempfile.NamedTemporaryFile(
            prefix="test_ca_cert", suffix=".pem", dir=out_dir
        ).name
        key_file = tempfile.NamedTemporaryFile(
            prefix="test_ca_key", suffix=".pem", dir=out_dir
        ).name

        if common_name is None:
            common_name = f"Test {alg} Root CA " + datetime.now().strftime(
                " %Y-%m-%d %H:%M:%S.%f"
            )

        ca_cert, ca_key = CertUtils.gen_ca_cert(
            alg=alg,
            key_out_file=key_file,
            cert_out_file=cert_file,
            days=valid_days,
            subject=x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, "San Diego"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OrganizationX"),
                    x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                ]
            ),
        )

        assert os.path.isfile(key_file), "Failed making Keyfile"
        assert os.path.isfile(cert_file), "Failed making CA Cert "
        print(f"Created test CA Cert: {cert_file} and Key: {key_file}")

        return cert_file, key_file

    @staticmethod
    def gen_user_cert_files(
        ca_cert_file, ca_key_file, alg="rsa", out_dir="/tmp/"
    ) -> tuple[str, str]:
        user_cert_file, user_key_file = CertUtils.gen_user_cert_py(
            alg=alg, ca_cert_file=ca_cert_file, ca_key_file=ca_key_file, out_dir=out_dir
        )
        assert os.path.isfile(user_cert_file), "Failed making User Cert File"
        assert os.path.isfile(user_key_file), "Failed making User Key File "
        print(f"Created test User Cert: {user_cert_file} and Key: {user_key_file}")

        return user_cert_file, user_key_file

    @staticmethod
    def gen_user_signed_certs(out_dir="/tmp/", alg="rsa"):
        # generate test CA and User Certificates signed by the CA
        ca_cert_file, ca_key_file = CertUtils.gen_test_ca(alg=alg, out_dir=out_dir)
        user_cert_file, user_key_file = CertUtils.gen_user_cert_files(
            alg=alg,
            ca_cert_file=ca_cert_file,
            ca_key_file=ca_key_file,
            out_dir=out_dir,
        )
        return ca_cert_file, user_cert_file, user_key_file

    @staticmethod
    def gen_tls_signed_certs(alg="ECDSA", out_dir="/tmp/"):
        # generate test CA and TLS Certificates signed by the CA
        ca_cert_file, ca_key_file = CertUtils.gen_test_ca(
            alg=alg,
            valid_days=365,
            common_name=f"Test TLS {alg} Root CA"
            + datetime.now().strftime(" %Y-%m-%d %H:%M:%S"),
            out_dir=out_dir,
        )
        user_cert_file, user_key_file = CertUtils.gen_user_cert_files(
            alg=alg, ca_cert_file=ca_cert_file, ca_key_file=ca_key_file, out_dir=out_dir
        )
        return ca_cert_file, user_cert_file, user_key_file

    @staticmethod
    def gen_https_server_certs(alg="ec", out_dir="/tmp/"):
        # generate test CA and TLS Certificates signed by the CA
        ca_cert_file, ca_key_file = CertUtils.gen_test_ca(
            alg=alg,
            valid_days=365,
            common_name="Test HTTPS Root CA"
            + datetime.now().strftime(" %Y-%m-%d %H:%M:%S"),
            out_dir=out_dir,
        )

        return ca_cert_file, ca_key_file

    @staticmethod
    def gen_syslog_root_certs(alg="ec", out_dir="/tmp/"):
        # generate test CA and Syslog Certificates signed by the CA
        ca_cert_file, ca_key_file = CertUtils.gen_test_ca(
            alg=alg,
            common_name="Test Syslog Root CA"
            + datetime.now().strftime(" %Y-%m-%d %H:%M:%S"),
            out_dir=out_dir,
        )
        return ca_cert_file, ca_key_file

    @staticmethod
    def gen_syslog_host_certs(root_key: str, root_cert: str, alg="ec", out_dir="/tmp/"):
        # generate test CA and Syslog Certificates signed by the CA
        ca_cert_file, ca_key_file = CertUtils.gen_user_cert_py(
            ca_cert_file=root_cert,
            ca_key_file=root_key,
            alg=alg,
            # common_name="Test Syslog Host "  + datetime.now().strftime(" %Y-%m-%d %H:%M:%S"),
            out_dir=out_dir,
        )
        return ca_cert_file, ca_key_file

    @staticmethod
    def generate_ssh_key_pair() -> tuple[str, str]:
        # Generate an RSA key pair
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

        # Get the public key in OpenSSH format
        public_key = private_key.public_key()
        ssh_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        ).decode()

        # Get the private key in PEM format
        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        return pem_private_key, ssh_public_key
